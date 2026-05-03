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
//! Limits are enforced via boa's loop iteration + recursion caps and a
//! hard cap on stringified output size. We intentionally don't try to
//! emulate every CloudFront builtin — fakecloud only needs the
//! pass-through shape so callers can validate request/response
//! transforms in tests.

use std::cell::RefCell;
use std::rc::Rc;

use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsValue, NativeFunction, Source};

const LOOP_ITERATION_LIMIT: u64 = 10_000_000;
const RECURSION_LIMIT: usize = 1_000;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Result of executing a CloudFront-style function. Either `output`
/// (the JSON-encoded handler return value) or `error` will be set;
/// `logs` is always populated (possibly empty) with whatever the user
/// JS wrote to `console.log` / `console.error`.
#[derive(Debug, Clone, Default)]
pub(crate) struct JsExecution {
    pub output: Option<String>,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

/// Run `handler(event)` defined in `code` against `event_json`.
///
/// `code` is the raw JavaScript source (already base64-decoded by the
/// caller). `event_json` is the JSON-encoded event object. Returns a
/// populated `JsExecution`; this function itself never panics on user
/// input — JS errors map to `error`, oversized outputs become an
/// error, and non-JSON event blobs are surfaced as an `error` too.
pub(crate) fn run_handler(code: &str, event_json: &[u8]) -> JsExecution {
    let logs: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let mut ctx = Context::default();
    ctx.runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_ITERATION_LIMIT);
    ctx.runtime_limits_mut()
        .set_recursion_limit(RECURSION_LIMIT);

    if let Err(err) = install_console(&mut ctx, &logs) {
        return JsExecution {
            error: Some(format!("failed to install console: {err}")),
            logs: logs.borrow().clone(),
            ..Default::default()
        };
    }

    if let Err(err) = ctx.eval(Source::from_bytes(code.as_bytes())) {
        return JsExecution {
            error: Some(format!("{}", err)),
            logs: logs.borrow().clone(),
            ..Default::default()
        };
    }

    let event_str = match std::str::from_utf8(event_json) {
        Ok(s) => s,
        Err(_) => {
            return JsExecution {
                error: Some("EventObject is not valid UTF-8".to_string()),
                logs: logs.borrow().clone(),
                ..Default::default()
            };
        }
    };
    // Wrap in parens so a top-level `{ ... }` object literal parses as
    // an expression rather than a block statement.
    let event_src = format!("({})", event_str);
    let event = match ctx.eval(Source::from_bytes(event_src.as_bytes())) {
        Ok(v) => v,
        Err(err) => {
            return JsExecution {
                error: Some(format!("invalid EventObject JSON: {err}")),
                logs: logs.borrow().clone(),
                ..Default::default()
            };
        }
    };

    let handler = match ctx.global_object().get(js_string!("handler"), &mut ctx) {
        Ok(h) => h,
        Err(err) => {
            return JsExecution {
                error: Some(format!("function handler is not defined: {err}")),
                logs: logs.borrow().clone(),
                ..Default::default()
            };
        }
    };
    let Some(handler_fn) = handler.as_callable() else {
        return JsExecution {
            error: Some("function handler is not callable".to_string()),
            logs: logs.borrow().clone(),
            ..Default::default()
        };
    };

    let returned = match handler_fn.call(&JsValue::undefined(), &[event], &mut ctx) {
        Ok(v) => v,
        Err(err) => {
            return JsExecution {
                error: Some(format!("{}", err)),
                logs: logs.borrow().clone(),
                ..Default::default()
            };
        }
    };

    let stringified = match stringify(&mut ctx, returned) {
        Ok(s) => s,
        Err(err) => {
            return JsExecution {
                error: Some(format!("failed to JSON.stringify result: {err}")),
                logs: logs.borrow().clone(),
                ..Default::default()
            };
        }
    };

    if stringified.len() > MAX_OUTPUT_BYTES {
        return JsExecution {
            error: Some(format!("function output exceeded {MAX_OUTPUT_BYTES} bytes")),
            logs: logs.borrow().clone(),
            ..Default::default()
        };
    }

    let captured = logs.borrow().clone();
    JsExecution {
        output: Some(stringified),
        error: None,
        logs: captured,
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
    }

    #[test]
    fn surfaces_thrown_error() {
        let exec = run_handler(r#"function handler() { throw new Error("boom"); }"#, b"{}");
        assert!(exec.output.is_none());
        let err = exec.error.expect("error");
        assert!(err.contains("boom"), "got {err}");
    }

    #[test]
    fn captures_console_log() {
        let exec = run_handler(
            r#"function handler(e) { console.log("a", "b"); return e; }"#,
            b"{}",
        );
        assert_eq!(exec.logs, vec!["a b".to_string()]);
        assert!(exec.error.is_none());
    }

    #[test]
    fn errors_when_handler_missing() {
        let exec = run_handler("var x = 1;", b"{}");
        assert!(exec.error.is_some());
    }

    #[test]
    fn errors_when_event_is_invalid_json() {
        let exec = run_handler(r#"function handler(e) { return e; }"#, b"not-json");
        assert!(exec.error.is_some());
    }
}
