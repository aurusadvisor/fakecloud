//! Minimal JavaScript runtime backing CloudFront Functions and
//! ConnectionFunctions. We embed `boa_engine` to actually execute the
//! user's `function handler(event) { ... }` against a caller-provided
//! event object, mirroring the real AWS shape:
//!
//! - decode the function source, eval it in a fresh `Context`;
//! - parse the event JSON into a JS value (`(<json>)`);
//! - call `handler(event)`;
//! - JSON.stringify the return value;
//! - capture `console.log/error` output as execution log lines.
//!
//! Limits are enforced in two layers:
//!
//! 1. boa's loop iteration + recursion caps trip on hot loops so the
//!    interpreter eventually returns control even under adversarial
//!    user JS.
//! 2. A wall-clock timeout: the actual execution runs on a dedicated
//!    OS thread; the calling thread waits on a `mpsc::sync_channel` via
//!    `recv_timeout`. If the JS doesn't finish in time we abandon the
//!    worker thread (best-effort — boa's iteration limit will eventually
//!    let it die) and return a timeout error.
//!
//! Real CloudFront Functions are bounded at ~1ms of CPU per request and
//! 2MB of memory. We mirror that with a 10ms wall-clock budget — looser
//! to avoid flakes on shared CI runners, still tight enough that
//! `while(1){}` is killed in tests.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsValue, NativeFunction, Source};

/// Hard wall-clock cap on a single TestFunction / TestConnectionFunction
/// invocation. AWS bounds production traffic at ~1ms of CPU; we set
/// 250ms so CI runners with noisy neighbours don't false-alarm on
/// well-formed handlers, while `while(1){}` is still killed well
/// inside any reasonable test timeout.
pub(crate) const EXECUTION_TIMEOUT: Duration = Duration::from_millis(250);

/// boa loop iteration cap. Tight enough that `while(1){}` exits the VM
/// well within the wall-clock budget on any reasonable host, loose
/// enough that small loops in real handlers run to completion.
const LOOP_ITERATION_LIMIT: u64 = 200_000;
const RECURSION_LIMIT: usize = 1_000;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Result of executing a CloudFront-style function. Either `output`
/// (the JSON-encoded handler return value) or `error` will be set;
/// `logs` is always populated (possibly empty) with whatever the user
/// JS wrote to `console.log` / `console.error`. On error we also push
/// a synthetic log line so callers that surface logs alone still see
/// the failure.
#[derive(Debug, Clone, Default)]
pub(crate) struct JsExecution {
    pub output: Option<String>,
    pub error: Option<String>,
    pub logs: Vec<String>,
    /// Synthetic compute utilisation in percent. Real CloudFront
    /// returns a number 0..=100 representing the share of the per-
    /// request CPU budget consumed. We approximate it by linear
    /// interpolation against `EXECUTION_TIMEOUT` and saturate at 100,
    /// then deliberately flip past 100 on errors / timeouts so callers
    /// can detect failure from the metric alone.
    pub compute_utilization: u32,
}

/// Run `handler(event)` defined in `code` against `event_json` on a
/// dedicated worker thread, enforcing `EXECUTION_TIMEOUT`.
pub(crate) fn run_handler(code: &str, event_json: &[u8]) -> JsExecution {
    let code = code.to_owned();
    let event = event_json.to_vec();
    let (tx, rx) = mpsc::sync_channel::<JsExecution>(1);

    // Each call gets its own thread because boa's `Context` holds
    // `Rc`s and is `!Send`. We can't pre-spawn a worker pool without
    // marshalling the script + event via channels anyway, so a fresh
    // thread per call is the simpler shape.
    let started = Instant::now();
    let _ = std::thread::Builder::new()
        .name("cloudfront-js".to_string())
        // Boa's bytecode VM is recursive so we want a generous stack.
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let result = run_handler_blocking(&code, &event, started);
            // If the receiver has timed out and gone away the send
            // simply errors; we don't care — the worker is being
            // abandoned.
            let _ = tx.send(result);
        });

    match rx.recv_timeout(EXECUTION_TIMEOUT) {
        Ok(mut exec) => {
            // Floor compute_utilization at 1% on success so callers
            // don't mistake a successful run for an unrun one.
            if exec.error.is_none() && exec.compute_utilization == 0 {
                exec.compute_utilization = 1;
            }
            exec
        }
        Err(_) => {
            let msg = format!(
                "function execution exceeded the {}ms time limit",
                EXECUTION_TIMEOUT.as_millis()
            );
            JsExecution {
                output: None,
                error: Some(msg.clone()),
                logs: vec![format!("ERROR: {msg}")],
                compute_utilization: 101,
            }
        }
    }
}

fn run_handler_blocking(code: &str, event_json: &[u8], started: Instant) -> JsExecution {
    let logs: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let mut ctx = Context::default();
    ctx.runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_ITERATION_LIMIT);
    ctx.runtime_limits_mut()
        .set_recursion_limit(RECURSION_LIMIT);

    if let Err(err) = install_console(&mut ctx, &logs) {
        return error_execution(format!("failed to install console: {err}"), &logs, started);
    }

    if let Err(err) = ctx.eval(Source::from_bytes(code.as_bytes())) {
        return error_execution(format!("{}", err), &logs, started);
    }

    let event_str = match std::str::from_utf8(event_json) {
        Ok(s) => s,
        Err(_) => {
            return error_execution("EventObject is not valid UTF-8".to_string(), &logs, started);
        }
    };
    // Wrap in parens so a top-level `{ ... }` object literal parses as
    // an expression rather than a block statement.
    let event_src = format!("({})", event_str);
    let event = match ctx.eval(Source::from_bytes(event_src.as_bytes())) {
        Ok(v) => v,
        Err(err) => {
            return error_execution(format!("invalid EventObject JSON: {err}"), &logs, started);
        }
    };

    let handler = match ctx.global_object().get(js_string!("handler"), &mut ctx) {
        Ok(h) => h,
        Err(err) => {
            return error_execution(
                format!("function handler is not defined: {err}"),
                &logs,
                started,
            );
        }
    };
    let Some(handler_fn) = handler.as_callable() else {
        return error_execution(
            "function handler is not callable".to_string(),
            &logs,
            started,
        );
    };

    let returned = match handler_fn.call(&JsValue::undefined(), &[event], &mut ctx) {
        Ok(v) => v,
        Err(err) => {
            return error_execution(format!("{}", err), &logs, started);
        }
    };

    let stringified = match stringify(&mut ctx, returned) {
        Ok(s) => s,
        Err(err) => {
            return error_execution(
                format!("failed to JSON.stringify result: {err}"),
                &logs,
                started,
            );
        }
    };

    if stringified.len() > MAX_OUTPUT_BYTES {
        return error_execution(
            format!("function output exceeded {MAX_OUTPUT_BYTES} bytes"),
            &logs,
            started,
        );
    }

    let captured = logs.borrow().clone();
    JsExecution {
        output: Some(stringified),
        error: None,
        logs: captured,
        compute_utilization: utilization_pct(started.elapsed()),
    }
}

fn error_execution(msg: String, logs: &Rc<RefCell<Vec<String>>>, started: Instant) -> JsExecution {
    let mut captured = logs.borrow().clone();
    captured.push(format!("ERROR: {msg}"));
    // Saturate past 100 on any failure so the metric alone signals the
    // run did not complete cleanly, regardless of how fast it failed.
    let elapsed_pct = utilization_pct(started.elapsed());
    let pct = elapsed_pct.max(101);
    JsExecution {
        output: None,
        error: Some(msg),
        logs: captured,
        compute_utilization: pct,
    }
}

fn utilization_pct(elapsed: Duration) -> u32 {
    let limit_us = EXECUTION_TIMEOUT.as_micros().max(1);
    let used_us = elapsed.as_micros();
    let pct = (used_us * 100) / limit_us;
    if pct > 100 {
        100
    } else {
        pct as u32
    }
}

fn install_console(
    ctx: &mut Context,
    logs: &Rc<RefCell<Vec<String>>>,
) -> Result<(), boa_engine::JsError> {
    let logs_log = Rc::clone(logs);
    let log_fn = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let mut parts: Vec<String> = Vec::with_capacity(args.len());
            for a in args {
                let s = a
                    .to_string(ctx)
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();
                parts.push(s);
            }
            logs_log.borrow_mut().push(parts.join(" "));
            Ok(JsValue::undefined())
        })
    };
    let logs_err = Rc::clone(logs);
    let err_fn = unsafe {
        NativeFunction::from_closure(move |_this, args, ctx| {
            let mut parts: Vec<String> = Vec::with_capacity(args.len());
            for a in args {
                let s = a
                    .to_string(ctx)
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_default();
                parts.push(s);
            }
            logs_err.borrow_mut().push(parts.join(" "));
            Ok(JsValue::undefined())
        })
    };

    let console = ObjectInitializer::new(ctx)
        .function(log_fn, js_string!("log"), 0)
        .function(err_fn, js_string!("error"), 0)
        .build();
    ctx.register_global_property(js_string!("console"), console, Attribute::all())?;
    Ok(())
}

fn stringify(ctx: &mut Context, value: JsValue) -> Result<String, boa_engine::JsError> {
    let stringify = ctx.eval(Source::from_bytes(b"JSON.stringify"))?;
    let Some(stringify_fn) = stringify.as_callable() else {
        return Err(boa_engine::JsNativeError::typ()
            .with_message("JSON.stringify missing")
            .into());
    };
    let result = stringify_fn.call(&JsValue::undefined(), &[value], ctx)?;
    if result.is_undefined() {
        // JSON.stringify(undefined) yields undefined; treat as empty.
        return Ok(String::new());
    }
    Ok(result.to_string(ctx)?.to_std_string_escaped())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_modified_event_as_json() {
        let exec = run_handler(
            r#"function handler(e) { e.x = "y"; return e; }"#,
            br#"{"headers":{}}"#,
        );
        assert!(exec.error.is_none(), "unexpected error: {:?}", exec.error);
        let out = exec.output.expect("output");
        assert!(out.contains("\"x\":\"y\""), "got {out}");
        assert!(
            exec.compute_utilization <= 100,
            "got {}",
            exec.compute_utilization
        );
    }

    #[test]
    fn modifies_request_headers_aws_shape() {
        // Mirrors the real CloudFront Functions request shape so
        // callers can validate header rewrites in tests.
        let exec = run_handler(
            r#"function handler(event) {
                event.request.headers["x-foo"] = {value: "bar"};
                return event.request;
            }"#,
            br#"{"version":"1.0","context":{},"viewer":{},"request":{"method":"GET","uri":"/","querystring":{},"headers":{},"cookies":{}}}"#,
        );
        assert!(exec.error.is_none(), "unexpected error: {:?}", exec.error);
        let out = exec.output.expect("output");
        assert!(out.contains("\"x-foo\""), "got {out}");
        assert!(out.contains("\"bar\""), "got {out}");
    }

    #[test]
    fn surfaces_thrown_error() {
        let exec = run_handler(r#"function handler() { throw new Error("boom"); }"#, b"{}");
        assert!(exec.output.is_none());
        let err = exec.error.expect("error");
        assert!(err.contains("boom"), "got {err}");
        assert!(
            exec.logs.iter().any(|l| l.contains("boom")),
            "expected error in logs, got {:?}",
            exec.logs
        );
        assert!(
            exec.compute_utilization > 100,
            "expected >100 on error, got {}",
            exec.compute_utilization
        );
    }

    #[test]
    fn captures_console_log() {
        let exec = run_handler(
            r#"function handler(e) { console.log("a", "b"); return e; }"#,
            b"{}",
        );
        assert!(exec.error.is_none());
        assert!(exec.logs.iter().any(|l| l == "a b"));
    }

    #[test]
    fn errors_when_handler_missing() {
        let exec = run_handler("var x = 1;", b"{}");
        assert!(exec.error.is_some());
        assert!(
            exec.compute_utilization > 100,
            "expected >100 on error, got {}",
            exec.compute_utilization
        );
    }

    #[test]
    fn errors_when_event_is_invalid_json() {
        let exec = run_handler(r#"function handler(e) { return e; }"#, b"not-json");
        assert!(exec.error.is_some());
    }

    #[test]
    fn infinite_loop_is_killed_by_timeout() {
        let exec = run_handler(r#"function handler() { while(1){} }"#, b"{}");
        assert!(exec.output.is_none());
        let err = exec.error.expect("error");
        // Either the wall-clock recv_timeout fired or boa's iteration
        // cap tripped — both are acceptable kill signals; in either
        // case ComputeUtilization saturates past 100 and an error log
        // is present.
        assert!(
            err.contains("time limit") || err.contains("limit") || err.contains("iteration"),
            "expected timeout/iteration error, got {err}"
        );
        assert!(
            exec.compute_utilization > 100,
            "expected >100 after timeout, got {}",
            exec.compute_utilization
        );
        assert!(
            !exec.logs.is_empty(),
            "expected error log line, got empty logs"
        );
    }
}
