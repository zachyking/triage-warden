//! Parse email action.
//!
//! This action parses raw email content to extract headers, body, attachments, and URLs.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, instrument};

/// Maximum length for email body content in action output to prevent sensitive data exposure.
const MAX_BODY_OUTPUT_LENGTH: usize = 200;

/// Truncation suffix appended when content is truncated.
const TRUNCATION_SUFFIX: &str = "...";

/// Truncates a string to the specified maximum length, adding a suffix if truncated.
/// Handles UTF-8 character boundaries safely to prevent invalid string slicing.
fn truncate_body_for_output(content: &str) -> String {
    if content.len() <= MAX_BODY_OUTPUT_LENGTH {
        content.to_string()
    } else {
        // Find a safe truncation point that doesn't break UTF-8
        let mut end = MAX_BODY_OUTPUT_LENGTH;
        while !content.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}{}", &content[..end], TRUNCATION_SUFFIX)
    }
}

/// Parsed email structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEmail {
    /// Email headers.
    pub headers: HashMap<String, String>,
    /// Plain text body.
    pub body_text: Option<String>,
    /// HTML body.
    pub body_html: Option<String>,
    /// List of attachments.
    pub attachments: Vec<Attachment>,
    /// Extracted URLs from the email.
    pub urls: Vec<String>,
    /// Sender address.
    pub from: Option<String>,
    /// Recipient addresses.
    pub to: Vec<String>,
    /// CC addresses.
    pub cc: Vec<String>,
    /// Subject line.
    pub subject: Option<String>,
    /// Message ID.
    pub message_id: Option<String>,
    /// Date header.
    pub date: Option<String>,
    /// Reply-To address.
    pub reply_to: Option<String>,
    /// Return-Path address.
    pub return_path: Option<String>,
}

/// Email attachment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Filename of the attachment.
    pub filename: String,
    /// Content type (MIME type).
    pub content_type: String,
    /// Size in bytes.
    pub size: usize,
    /// SHA-256 hash of the content.
    pub sha256: Option<String>,
}

/// Action to parse raw email content.
pub struct ParseEmailAction;

impl ParseEmailAction {
    /// Creates a new parse email action.
    pub fn new() -> Self {
        Self
    }

    /// Parses raw email content (RFC 5322 format).
    fn parse_raw_email(&self, raw_email: &str) -> Result<ParsedEmail, ActionError> {
        let mut headers = HashMap::new();
        let mut body_text = None;
        let mut body_html = None;
        let mut attachments = Vec::new();
        let mut urls = Vec::new();

        // Split headers and body
        let parts: Vec<&str> = raw_email.splitn(2, "\r\n\r\n").collect();
        let (header_section, body_section) = if parts.len() == 2 {
            (parts[0], Some(parts[1]))
        } else {
            // Try with just \n\n
            let parts: Vec<&str> = raw_email.splitn(2, "\n\n").collect();
            if parts.len() == 2 {
                (parts[0], Some(parts[1]))
            } else {
                (raw_email, None)
            }
        };

        // Parse headers (handle folded headers)
        let mut current_header: Option<(String, String)> = None;
        for line in header_section.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of previous header
                if let Some((_, ref mut value)) = current_header {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            } else if let Some((name, value)) = line.split_once(':') {
                // Save previous header
                if let Some((prev_name, prev_value)) = current_header.take() {
                    headers.insert(prev_name.to_lowercase(), prev_value);
                }
                current_header = Some((name.trim().to_string(), value.trim().to_string()));
            }
        }
        // Save last header
        if let Some((name, value)) = current_header {
            headers.insert(name.to_lowercase(), value);
        }

        // Extract common headers
        let from = headers.get("from").cloned();
        let to = Self::parse_address_list(headers.get("to").map(|s| s.as_str()));
        let cc = Self::parse_address_list(headers.get("cc").map(|s| s.as_str()));
        let subject = headers.get("subject").cloned();
        let message_id = headers.get("message-id").cloned();
        let date = headers.get("date").cloned();
        let reply_to = headers.get("reply-to").cloned();
        let return_path = headers.get("return-path").cloned();

        // Process body
        if let Some(body) = body_section {
            let content_type = headers
                .get("content-type")
                .map(|s| s.to_lowercase())
                .unwrap_or_default();

            if content_type.contains("multipart/") {
                // Parse multipart message
                let (text, html, atts) = self.parse_multipart(body, &content_type);
                body_text = text;
                body_html = html;
                attachments = atts;
            } else if content_type.contains("text/html") {
                body_html = Some(body.to_string());
            } else {
                body_text = Some(body.to_string());
            }

            // Extract URLs from body
            urls = self.extract_urls(body);
        }

        Ok(ParsedEmail {
            headers,
            body_text,
            body_html,
            attachments,
            urls,
            from,
            to,
            cc,
            subject,
            message_id,
            date,
            reply_to,
            return_path,
        })
    }

    /// Parses structured email data (JSON format).
    fn parse_structured_email(&self, data: &serde_json::Value) -> Result<ParsedEmail, ActionError> {
        let mut headers = HashMap::new();
        let mut urls = Vec::new();

        // Extract headers if provided
        if let Some(header_obj) = data.get("headers").and_then(|h| h.as_object()) {
            for (key, value) in header_obj {
                if let Some(v) = value.as_str() {
                    headers.insert(key.to_lowercase(), v.to_string());
                }
            }
        }

        let from = data
            .get("from")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| headers.get("from").cloned());

        let to = data
            .get("to")
            .and_then(|v| {
                if let Some(arr) = v.as_array() {
                    Some(
                        arr.iter()
                            .filter_map(|a| a.as_str())
                            .map(String::from)
                            .collect(),
                    )
                } else {
                    v.as_str().map(|s| Self::parse_address_list(Some(s)))
                }
            })
            .unwrap_or_default();

        let cc = data
            .get("cc")
            .and_then(|v| {
                if let Some(arr) = v.as_array() {
                    Some(
                        arr.iter()
                            .filter_map(|a| a.as_str())
                            .map(String::from)
                            .collect(),
                    )
                } else {
                    v.as_str().map(|s| Self::parse_address_list(Some(s)))
                }
            })
            .unwrap_or_default();

        let subject = data
            .get("subject")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| headers.get("subject").cloned());

        let body_text = data.get("body_text").and_then(|v| v.as_str()).map(|s| {
            urls.extend(self.extract_urls(s));
            s.to_string()
        });

        let body_html = data.get("body_html").and_then(|v| v.as_str()).map(|s| {
            urls.extend(self.extract_urls(s));
            s.to_string()
        });

        // Also check "body" field
        if body_text.is_none() && body_html.is_none() {
            if let Some(body) = data.get("body").and_then(|v| v.as_str()) {
                urls.extend(self.extract_urls(body));
            }
        }

        let attachments = data
            .get("attachments")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        Some(Attachment {
                            filename: a.get("filename")?.as_str()?.to_string(),
                            content_type: a
                                .get("content_type")
                                .and_then(|c| c.as_str())
                                .unwrap_or("application/octet-stream")
                                .to_string(),
                            size: a.get("size").and_then(|s| s.as_u64()).unwrap_or(0) as usize,
                            sha256: a.get("sha256").and_then(|h| h.as_str()).map(String::from),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Deduplicate URLs
        urls.sort();
        urls.dedup();

        // Extract values from headers before moving it
        let message_id = data
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| headers.get("message-id").cloned());
        let date = data
            .get("date")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| headers.get("date").cloned());
        let reply_to = headers.get("reply-to").cloned();
        let return_path = headers.get("return-path").cloned();

        Ok(ParsedEmail {
            headers,
            body_text: body_text
                .or_else(|| data.get("body").and_then(|v| v.as_str()).map(String::from)),
            body_html,
            attachments,
            urls,
            from,
            to,
            cc,
            subject,
            message_id,
            date,
            reply_to,
            return_path,
        })
    }

    /// Parses a comma-separated address list.
    fn parse_address_list(addresses: Option<&str>) -> Vec<String> {
        addresses
            .map(|s| {
                s.split(',')
                    .map(|addr| addr.trim().to_string())
                    .filter(|addr| !addr.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parses a multipart message body.
    fn parse_multipart(
        &self,
        body: &str,
        content_type: &str,
    ) -> (Option<String>, Option<String>, Vec<Attachment>) {
        let mut text_body = None;
        let mut html_body = None;
        let mut attachments = Vec::new();

        // Extract boundary from content-type
        let boundary = content_type.split(';').find_map(|part| {
            let part = part.trim();
            if part.to_lowercase().starts_with("boundary=") {
                let boundary = part[9..].trim_matches('"').trim_matches('\'');
                Some(boundary.to_string())
            } else {
                None
            }
        });

        if let Some(boundary) = boundary {
            let delimiter = format!("--{}", boundary);
            let parts: Vec<&str> = body.split(&delimiter).collect();

            for part in parts.iter().skip(1) {
                // Skip preamble
                if part.starts_with("--") {
                    // End boundary
                    continue;
                }

                // Split part headers and body
                let part_sections: Vec<&str> = part.splitn(2, "\r\n\r\n").collect();
                let (part_headers, part_body) = if part_sections.len() == 2 {
                    (part_sections[0], part_sections[1])
                } else {
                    let part_sections: Vec<&str> = part.splitn(2, "\n\n").collect();
                    if part_sections.len() == 2 {
                        (part_sections[0], part_sections[1])
                    } else {
                        continue;
                    }
                };

                let part_content_type = part_headers
                    .lines()
                    .find_map(|line| {
                        if line.to_lowercase().starts_with("content-type:") {
                            Some(line[13..].trim().to_lowercase())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();

                let content_disposition = part_headers.lines().find_map(|line| {
                    if line.to_lowercase().starts_with("content-disposition:") {
                        Some(line[20..].trim().to_lowercase())
                    } else {
                        None
                    }
                });

                if content_disposition
                    .as_ref()
                    .map(|d| d.contains("attachment"))
                    .unwrap_or(false)
                {
                    // This is an attachment
                    let filename = content_disposition
                        .as_ref()
                        .and_then(|d| {
                            d.split(';').find_map(|p| {
                                let p = p.trim();
                                p.strip_prefix("filename=")
                                    .map(|s| s.trim_matches('"').to_string())
                            })
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    attachments.push(Attachment {
                        filename,
                        content_type: part_content_type
                            .split(';')
                            .next()
                            .unwrap_or("application/octet-stream")
                            .to_string(),
                        size: part_body.len(),
                        sha256: None, // Would need to decode and hash for real implementation
                    });
                } else if part_content_type.contains("text/html") {
                    html_body = Some(part_body.trim().to_string());
                } else if part_content_type.contains("text/plain") || part_content_type.is_empty() {
                    text_body = Some(part_body.trim().to_string());
                } else if part_content_type.contains("multipart/") {
                    // Nested multipart - recurse
                    let (nested_text, nested_html, nested_attachments) =
                        self.parse_multipart(part_body, &part_content_type);
                    if text_body.is_none() {
                        text_body = nested_text;
                    }
                    if html_body.is_none() {
                        html_body = nested_html;
                    }
                    attachments.extend(nested_attachments);
                }
            }
        }

        (text_body, html_body, attachments)
    }

    /// Extracts URLs from text content.
    fn extract_urls(&self, content: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // Simple URL extraction patterns
        // Match http/https URLs
        let url_pattern = regex::Regex::new(r#"(?i)(https?://[^\s<>"'\)]+)"#).unwrap();

        for cap in url_pattern.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                let url_str = url.as_str().trim_end_matches(['.', ',', ';']);
                urls.push(url_str.to_string());
            }
        }

        // Also look for href attributes in HTML
        let href_pattern = regex::Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
        for cap in href_pattern.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                let url_str = url.as_str();
                if url_str.starts_with("http://") || url_str.starts_with("https://") {
                    urls.push(url_str.to_string());
                }
            }
        }

        // Deduplicate
        urls.sort();
        urls.dedup();
        urls
    }
}

impl Default for ParseEmailAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for ParseEmailAction {
    fn name(&self) -> &str {
        "parse_email"
    }

    fn description(&self) -> &str {
        "Parses raw email content to extract headers, body, attachments, and URLs"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::optional(
                "raw_email",
                "Raw email content in RFC 5322 format",
                ParameterType::String,
                serde_json::json!(null),
            ),
            ParameterDef::optional(
                "email_data",
                "Structured email data as JSON object",
                ParameterType::Object,
                serde_json::json!(null),
            ),
        ]
    }

    fn validate(&self, context: &ActionContext) -> Result<(), ActionError> {
        let has_raw = context.get_param("raw_email").is_some()
            && !context.get_param("raw_email").unwrap().is_null();
        let has_structured = context.get_param("email_data").is_some()
            && !context.get_param("email_data").unwrap().is_null();

        if !has_raw && !has_structured {
            return Err(ActionError::InvalidParameters(
                "Either 'raw_email' or 'email_data' must be provided".to_string(),
            ));
        }

        Ok(())
    }

    fn supports_rollback(&self) -> bool {
        false // Parsing is read-only, no rollback needed
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();

        // Try to parse raw email first, then structured data
        let parsed = if let Some(raw) = context.get_string("raw_email") {
            debug!("Parsing raw email content ({} bytes)", raw.len());
            self.parse_raw_email(&raw)?
        } else if let Some(data) = context.get_param("email_data") {
            debug!("Parsing structured email data");
            self.parse_structured_email(data)?
        } else {
            return Err(ActionError::InvalidParameters(
                "No email content provided".to_string(),
            ));
        };

        info!(
            "Parsed email: from={:?}, subject={:?}, {} URLs, {} attachments",
            parsed.from,
            parsed.subject,
            parsed.urls.len(),
            parsed.attachments.len()
        );

        let mut output = HashMap::new();
        output.insert(
            "headers".to_string(),
            serde_json::to_value(&parsed.headers).unwrap_or_default(),
        );
        output.insert("from".to_string(), serde_json::json!(parsed.from));
        output.insert(
            "to".to_string(),
            serde_json::to_value(&parsed.to).unwrap_or_default(),
        );
        output.insert(
            "cc".to_string(),
            serde_json::to_value(&parsed.cc).unwrap_or_default(),
        );
        output.insert("subject".to_string(), serde_json::json!(parsed.subject));
        output.insert(
            "message_id".to_string(),
            serde_json::json!(parsed.message_id),
        );
        output.insert("date".to_string(), serde_json::json!(parsed.date));
        // Truncate body content to prevent sensitive data exposure in responses
        let truncated_body_text = parsed
            .body_text
            .as_ref()
            .map(|b| truncate_body_for_output(b));
        let truncated_body_html = parsed
            .body_html
            .as_ref()
            .map(|b| truncate_body_for_output(b));

        output.insert(
            "body_text".to_string(),
            serde_json::json!(truncated_body_text),
        );
        output.insert(
            "body_html".to_string(),
            serde_json::json!(truncated_body_html),
        );

        // Include truncation metadata
        output.insert(
            "body_text_truncated".to_string(),
            serde_json::json!(parsed
                .body_text
                .as_ref()
                .map(|b| b.len() > MAX_BODY_OUTPUT_LENGTH)
                .unwrap_or(false)),
        );
        output.insert(
            "body_html_truncated".to_string(),
            serde_json::json!(parsed
                .body_html
                .as_ref()
                .map(|b| b.len() > MAX_BODY_OUTPUT_LENGTH)
                .unwrap_or(false)),
        );
        output.insert(
            "original_body_text_length".to_string(),
            serde_json::json!(parsed.body_text.as_ref().map(|b| b.len())),
        );
        output.insert(
            "original_body_html_length".to_string(),
            serde_json::json!(parsed.body_html.as_ref().map(|b| b.len())),
        );
        output.insert(
            "attachments".to_string(),
            serde_json::to_value(&parsed.attachments).unwrap_or_default(),
        );
        output.insert(
            "urls".to_string(),
            serde_json::to_value(&parsed.urls).unwrap_or_default(),
        );
        output.insert("reply_to".to_string(), serde_json::json!(parsed.reply_to));
        output.insert(
            "return_path".to_string(),
            serde_json::json!(parsed.return_path),
        );

        let message = format!(
            "Parsed email from {:?} with subject {:?}",
            parsed.from, parsed.subject
        );

        Ok(ActionResult::success(
            self.name(),
            &message,
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_parse_raw_email() {
        let action = ParseEmailAction::new();

        let raw_email = r#"From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test123@example.com>
Content-Type: text/plain

Hello, this is a test email.
Check out https://example.com for more info.
"#;

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("raw_email", serde_json::json!(raw_email));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("from").and_then(|v| v.as_str()),
            Some("sender@example.com")
        );
        assert_eq!(
            result.output.get("subject").and_then(|v| v.as_str()),
            Some("Test Email")
        );

        let urls = result.output.get("urls").and_then(|v| v.as_array());
        assert!(urls.is_some());
        assert!(urls
            .unwrap()
            .iter()
            .any(|u| u.as_str() == Some("https://example.com")));
    }

    #[tokio::test]
    async fn test_parse_structured_email() {
        let action = ParseEmailAction::new();

        let email_data = serde_json::json!({
            "from": "sender@example.com",
            "to": ["recipient1@example.com", "recipient2@example.com"],
            "subject": "Important Notice",
            "body_text": "Please review the attached document.",
            "body_html": "<p>Please review the attached document.</p>",
            "attachments": [
                {
                    "filename": "document.pdf",
                    "content_type": "application/pdf",
                    "size": 12345
                }
            ]
        });

        let context = ActionContext::new(Uuid::new_v4()).with_param("email_data", email_data);

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("from").and_then(|v| v.as_str()),
            Some("sender@example.com")
        );

        let to = result.output.get("to").and_then(|v| v.as_array());
        assert!(to.is_some());
        assert_eq!(to.unwrap().len(), 2);

        let attachments = result.output.get("attachments").and_then(|v| v.as_array());
        assert!(attachments.is_some());
        assert_eq!(attachments.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_multipart_email() {
        let action = ParseEmailAction::new();

        let raw_email = r#"From: sender@example.com
To: recipient@example.com
Subject: Multipart Test
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text version.
--boundary123
Content-Type: text/html

<html><body><p>HTML version.</p></body></html>
--boundary123--
"#;

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("raw_email", serde_json::json!(raw_email));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert!(result.output.get("body_text").is_some());
        assert!(result.output.get("body_html").is_some());
    }

    #[tokio::test]
    async fn test_extract_urls() {
        let action = ParseEmailAction::new();

        let raw_email = r#"From: sender@example.com
To: recipient@example.com
Subject: Links Test
Content-Type: text/html

<html>
<body>
<p>Visit our site: https://example.com/page</p>
<a href="https://malicious-site.com/phish">Click here</a>
<p>Also check http://another-site.org/info</p>
</body>
</html>
"#;

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("raw_email", serde_json::json!(raw_email));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let urls = result.output.get("urls").and_then(|v| v.as_array());
        assert!(urls.is_some());
        let urls = urls.unwrap();
        assert!(urls.len() >= 2);
    }

    #[tokio::test]
    async fn test_missing_email_content() {
        let action = ParseEmailAction::new();
        let context = ActionContext::new(Uuid::new_v4());

        let result = action.validate(&context);
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_folded_headers() {
        let action = ParseEmailAction::new();

        let raw_email = r#"From: sender@example.com
To: recipient@example.com
Subject: This is a very long subject line that
 continues on the next line
Message-ID: <test@example.com>

Body content.
"#;

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("raw_email", serde_json::json!(raw_email));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let subject = result.output.get("subject").and_then(|v| v.as_str());
        assert!(subject.is_some());
        assert!(subject.unwrap().contains("continues"));
    }
}
