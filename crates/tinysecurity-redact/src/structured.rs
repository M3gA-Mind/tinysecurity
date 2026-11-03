//! Bounded JSON traversal with distinct approval and logging surfaces.
use crate::{MARKER, MAX_DEPTH, Redactor, bounded, output_bounded};
use serde_json::{Map, Value};
use tinysecurity_bus::{Error, RedactMode, Result, ScanResponse};
const CONTENT_KEYS: &[&str] = &[
    "body",
    "content",
    "description",
    "plaintext",
    "text",
    "message",
    "messages",
    "coverletter",
    "note",
    "reason",
    "html",
    "html_body",
    "snippet",
    "subject",
    "title",
    "recipient",
    "recipients",
    "to",
    "cc",
    "bcc",
    "from",
    "sender",
    "address",
    "email",
    "phone",
    "contact",
    "contacts",
    "name",
    "first_name",
    "last_name",
    "full_name",
    "displayname",
    "bio",
    "avatar",
    "links",
    "tags",
    "channel_name",
    "user",
    "user_id",
    "userid",
    "username",
    "thread_id",
    "thread_ts",
    "conversation_id",
    "auth",
    "code",
    "attachment",
    "attachments",
    "file_to_upload",
    "file_url",
    "public_url",
    "signed_url",
    "presigned_url",
    // Query names commonly used as bearer-capability parts of S3, GCS and
    // Azure signed URLs. These are sensitive even when callers split a URL
    // into a structured argument map.
    "x_amz_algorithm",
    "x_amz_credential",
    "x_amz_date",
    "x_amz_expires",
    "x_amz_security_token",
    "x_amz_signature",
    "x_amz_signedheaders",
    "x_goog_algorithm",
    "x_goog_credential",
    "x_goog_date",
    "x_goog_expires",
    "x_goog_signature",
    "x_goog_signedheaders",
    "signature",
    "sig",
    "sas_token",
];
/// Matches after lowercasing and dropping `-`/`_`, so `X-Api-Key`, `api_key` and
/// `apiKey` are one key. Exact match only: `cancellation_token` is not a credential.
fn credential_key(key: &str) -> bool {
    let key: String = key
        .chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(
        key.as_str(),
        "apikey"
            | "apisecret"
            | "xapikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "sessiontoken"
            | "authtoken"
            | "bearer"
            | "authorization"
            | "proxyauthorization"
            | "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "secretkey"
            | "credentials"
            | "privatekey"
            | "sessioncookie"
            | "cookie"
            | "setcookie"
    )
}
fn content_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    CONTENT_KEYS.iter().any(|candidate| {
        candidate
            .chars()
            .filter(|c| !matches!(c, '-' | '_'))
            .map(|c| c.to_ascii_lowercase())
            .eq(normalized.chars())
    })
}
pub(crate) fn sensitive_json_key(key: &str) -> bool {
    credential_key(key) || content_key(key)
}
fn marker(text: &str) -> bool {
    if text == MARKER {
        return true;
    }
    if matches!(text, "<redacted: number>" | "<redacted: bool>") {
        return true;
    }
    [
        "<redacted: string (",
        "<redacted: array (",
        "<redacted: object (",
    ]
    .iter()
    .zip([" chars)>", " items)>", " keys)>"])
    .any(|(prefix, suffix)| {
        text.strip_prefix(prefix)
            .and_then(|s| s.strip_suffix(suffix))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    })
}
fn count_marker(value: &Value) -> Value {
    Value::String(match value {
        Value::String(s) if marker(s) => s.clone(),
        Value::String(s) => format!("<redacted: string ({} chars)>", s.chars().count()),
        Value::Array(a) => format!("<redacted: array ({} items)>", a.len()),
        Value::Object(m) => format!("<redacted: object ({} keys)>", m.len()),
        Value::Number(_) => "<redacted: number>".into(),
        Value::Bool(_) => "<redacted: bool>".into(),
        Value::Null => return Value::Null,
    })
}
fn looks_json(text: &str) -> bool {
    // `[REDACTED]` opens a bracket but is never JSON, so redacted text that starts
    // with the marker must stay re-redactable (idempotence) instead of being refused.
    let head = text.trim_start();
    text != MARKER && !head.starts_with(MARKER) && head.starts_with(['{', '[', '"'])
}
fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
impl Redactor {
    pub(crate) fn structured_or_text(
        &self,
        text: &str,
        mode: &RedactMode,
        depth: usize,
    ) -> Result<String> {
        if depth > MAX_DEPTH {
            return Err(Error::InvalidArguments);
        }
        bounded(text)?;
        let required = matches!(
            mode,
            RedactMode::StructuredArguments
                | RedactMode::StructuredLogArguments
                | RedactMode::BrowserResult
        );
        if required || looks_json(text) {
            let mut value: Value =
                serde_json::from_str(text).map_err(|_| Error::InvalidArguments)?;
            let protected =
                if *mode == RedactMode::BrowserResult && value["status"] == "NeedsConfirmation" {
                    value
                        .pointer("/pending/token")
                        .and_then(Value::as_str)
                        .filter(|s| uuid(s) && self.0.patterns.literal(s) == *s)
                        .map(str::to_owned)
                } else {
                    None
                };
            if protected.is_some()
                && let Some(pending) = value.get_mut("pending").and_then(Value::as_object_mut)
            {
                pending.remove("token");
            }
            let mut result = self.walk(&value, mode, depth + 1)?;
            if let Some(token) = protected
                && let Some(pending) = result.get_mut("pending").and_then(Value::as_object_mut)
            {
                pending.insert("token".into(), Value::String(token));
            }
            let out = serde_json::to_string(&result).map_err(|_| Error::InvalidArguments)?;
            output_bounded(&out)?;
            Ok(out)
        } else {
            self.0.patterns.text(text)
        }
    }
    fn walk(&self, value: &Value, mode: &RedactMode, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::InvalidArguments);
        }
        match value {
            Value::Object(map) => {
                let mut out = Map::new();
                let mut counters = std::collections::BTreeMap::new();
                for (key, value) in map {
                    let sensitive = credential_key(key)
                        || (*mode == RedactMode::StructuredArguments && content_key(key));
                    let value = if sensitive {
                        if *mode == RedactMode::StructuredArguments {
                            let counted = count_marker(value);
                            if counted.is_null() && self.0.patterns.literal("null") != "null" {
                                Value::String(MARKER.into())
                            } else {
                                counted
                            }
                        } else {
                            Value::String(MARKER.into())
                        }
                    } else {
                        self.walk(value, mode, depth + 1)?
                    };
                    let base = self.0.patterns.text(key)?;
                    let mut sanitized = base.clone();
                    let suffix = counters.entry(base.clone()).or_insert(2usize);
                    while out.contains_key(&sanitized) {
                        sanitized = self.0.patterns.text(&format!("{base} ({suffix})"))?;
                        *suffix += 1;
                    }
                    out.insert(sanitized, value);
                }
                Ok(Value::Object(out))
            }
            Value::Array(items) => items
                .iter()
                .map(|v| self.walk(v, mode, depth + 1))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array),
            Value::String(text) => {
                // Embedded JSON is decoded before matching; quoted Unicode/JSON
                // escapes cannot carry a credential through an unknown field.
                self.structured_or_text(
                    text,
                    &if *mode == RedactMode::StructuredArguments {
                        RedactMode::StructuredArguments
                    } else {
                        RedactMode::Text
                    },
                    depth,
                )
                .map(Value::String)
                .or_else(|error| {
                    if looks_json(text) {
                        Err(error)
                    } else {
                        self.0.patterns.text(text).map(Value::String)
                    }
                })
            }
            other => {
                let serialized = other.to_string();
                if self.0.patterns.literal(&serialized) == serialized {
                    Ok(other.clone())
                } else {
                    Ok(Value::String(MARKER.into()))
                }
            }
        }
    }
    pub(crate) fn scan_value(
        &self,
        value: &Value,
        depth: usize,
        result: &mut ScanResponse,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::InvalidArguments);
        }
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    crate::prompt::merge(result, self.0.scanner.scan(key));
                    self.scan_value(value, depth + 1, result)?;
                }
            }
            Value::Array(items) => {
                for value in items {
                    self.scan_value(value, depth + 1, result)?;
                }
            }
            Value::String(text) => {
                crate::prompt::merge(result, self.0.scanner.scan(text));
                if looks_json(text) {
                    let nested: Value =
                        serde_json::from_str(text).map_err(|_| Error::InvalidArguments)?;
                    self.scan_value(&nested, depth + 1, result)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "structured_tests.rs"]
mod tests;
