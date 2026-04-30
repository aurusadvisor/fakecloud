use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::SentEmail;

use super::{extract_string_array, SesV2Service};

impl SesV2Service {
    /// Render `template_name` with `template_data` (JSON object string)
    /// against the caller's stored templates. Empty result on missing
    /// template or missing inputs — matches real SES which sends the
    /// raw template body when data is malformed.
    fn render_template_for_send(
        &self,
        account_id: &str,
        template_name: Option<&str>,
        template_data: Option<&str>,
    ) -> super::templates::RenderedTemplate {
        let empty = super::templates::RenderedTemplate {
            subject: None,
            html: None,
            text: None,
        };
        let Some(name) = template_name else {
            return empty;
        };
        let data_str = template_data.unwrap_or("{}");
        let accounts = self.state.read();
        let Some(state) = accounts.get(account_id) else {
            return empty;
        };
        let Some(template) = state.templates.get(name) else {
            return empty;
        };
        super::templates::render_template(template, data_str)
    }

    /// Reject the send if either account-level sending or the resolved
    /// configuration set's sending flag is paused. Real SES surfaces
    /// these as `AccountSendingPausedException` and
    /// `ConfigurationSetSendingPausedException` (HTTP 400).
    fn check_sending_enabled(
        &self,
        account_id: &str,
        config_set_name: Option<&str>,
    ) -> Option<AwsResponse> {
        let accounts = self.state.read();
        let state = accounts.get(account_id)?;
        if !state.account_settings.sending_enabled {
            return Some(Self::json_error(
                StatusCode::BAD_REQUEST,
                "AccountSendingPausedException",
                "Email sending is disabled for your account.",
            ));
        }
        if let Some(name) = config_set_name {
            if let Some(cs) = state.configuration_sets.get(name) {
                if !cs.sending_enabled {
                    return Some(Self::json_error(
                        StatusCode::BAD_REQUEST,
                        "ConfigurationSetSendingPausedException",
                        &format!("Email sending is disabled for the configuration set {name}."),
                    ));
                }
            }
        }
        None
    }

    pub(super) fn send_email(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body: Value = Self::parse_body(req)?;

        if !body["Content"].is_object()
            || (!body["Content"]["Simple"].is_object()
                && !body["Content"]["Raw"].is_object()
                && !body["Content"]["Template"].is_object())
        {
            return Ok(Self::json_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Content is required and must contain Simple, Raw, or Template",
            ));
        }

        let from = body["FromEmailAddress"].as_str().unwrap_or("").to_string();
        let config_set_name = body["ConfigurationSetName"].as_str().map(|s| s.to_string());
        if let Some(err) = self.check_sending_enabled(&req.account_id, config_set_name.as_deref()) {
            return Ok(err);
        }

        let to = extract_string_array(&body["Destination"]["ToAddresses"]);
        let cc = extract_string_array(&body["Destination"]["CcAddresses"]);
        let bcc = extract_string_array(&body["Destination"]["BccAddresses"]);

        let (subject, html_body, text_body, raw_data, template_name, template_data) =
            if body["Content"]["Simple"].is_object() {
                let simple = &body["Content"]["Simple"];
                let subject = simple["Subject"]["Data"].as_str().map(|s| s.to_string());
                let html = simple["Body"]["Html"]["Data"]
                    .as_str()
                    .map(|s| s.to_string());
                let text = simple["Body"]["Text"]["Data"]
                    .as_str()
                    .map(|s| s.to_string());
                (subject, html, text, None, None, None)
            } else if body["Content"]["Raw"].is_object() {
                let raw = body["Content"]["Raw"]["Data"]
                    .as_str()
                    .map(|s| s.to_string());
                (None, None, None, raw, None, None)
            } else if body["Content"]["Template"].is_object() {
                let tmpl = &body["Content"]["Template"];
                let tmpl_name = tmpl["TemplateName"].as_str().map(|s| s.to_string());
                let tmpl_data = tmpl["TemplateData"].as_str().map(|s| s.to_string());
                // Render via the same engine RenderEmailTemplate uses so
                // SentEmail captures the materialized subject/html/text.
                let rendered = self.render_template_for_send(
                    &req.account_id,
                    tmpl_name.as_deref(),
                    tmpl_data.as_deref(),
                );
                (
                    rendered.subject,
                    rendered.html,
                    rendered.text,
                    None,
                    tmpl_name,
                    tmpl_data,
                )
            } else {
                (None, None, None, None, None, None)
            };

        let message_id = uuid::Uuid::new_v4().to_string();

        let sent = SentEmail {
            message_id: message_id.clone(),
            from,
            to,
            cc,
            bcc,
            subject,
            html_body,
            text_body,
            raw_data,
            template_name,
            template_data,
            timestamp: Utc::now(),
        };

        // Event fanout: check suppression list, generate events, deliver to destinations
        if let Some(ref ctx) = self.delivery_ctx {
            crate::fanout::process_send_events(ctx, &sent, config_set_name.as_deref());
        }

        self.state
            .write()
            .get_or_create(&req.account_id)
            .sent_emails
            .push(sent);

        let response = json!({
            "MessageId": message_id,
        });

        Ok(AwsResponse::json(StatusCode::OK, response.to_string()))
    }

    pub(super) fn send_bulk_email(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body: Value = Self::parse_body(req)?;

        let from = body["FromEmailAddress"].as_str().unwrap_or("").to_string();
        let config_set_name = body["ConfigurationSetName"].as_str().map(|s| s.to_string());
        if let Some(err) = self.check_sending_enabled(&req.account_id, config_set_name.as_deref()) {
            return Ok(err);
        }

        let entries = match body["BulkEmailEntries"].as_array() {
            Some(arr) if !arr.is_empty() => arr.clone(),
            _ => {
                return Ok(Self::json_error(
                    StatusCode::BAD_REQUEST,
                    "BadRequestException",
                    "BulkEmailEntries is required and must not be empty",
                ));
            }
        };

        let mut results = Vec::new();

        for entry in &entries {
            let to = extract_string_array(&entry["Destination"]["ToAddresses"]);
            let cc = extract_string_array(&entry["Destination"]["CcAddresses"]);
            let bcc = extract_string_array(&entry["Destination"]["BccAddresses"]);

            let message_id = uuid::Uuid::new_v4().to_string();

            let template_name = body["DefaultContent"]["Template"]["TemplateName"]
                .as_str()
                .map(|s| s.to_string());
            let template_data = entry["ReplacementEmailContent"]["ReplacementTemplate"]
                ["ReplacementTemplateData"]
                .as_str()
                .or_else(|| body["DefaultContent"]["Template"]["TemplateData"].as_str())
                .map(|s| s.to_string());

            let rendered = self.render_template_for_send(
                &req.account_id,
                template_name.as_deref(),
                template_data.as_deref(),
            );

            let sent = SentEmail {
                message_id: message_id.clone(),
                from: from.clone(),
                to,
                cc,
                bcc,
                subject: rendered.subject,
                html_body: rendered.html,
                text_body: rendered.text,
                raw_data: None,
                template_name,
                template_data,
                timestamp: Utc::now(),
            };

            // Event fanout for each bulk entry
            if let Some(ref ctx) = self.delivery_ctx {
                crate::fanout::process_send_events(ctx, &sent, config_set_name.as_deref());
            }

            self.state
                .write()
                .get_or_create(&req.account_id)
                .sent_emails
                .push(sent);

            results.push(json!({
                "Status": "SUCCESS",
                "MessageId": message_id,
            }));
        }

        let response = json!({
            "BulkEmailEntryResults": results,
        });

        Ok(AwsResponse::json(StatusCode::OK, response.to_string()))
    }
}
