//! Bounded native secret/identifier redaction and contextual intent scanning.
//!
//! [`Redactor`] validates one immutable initialization registry. This crate does
//! no network I/O, authorization, protocol sanitation or skill-package scanning.
//!
//! ```
//! use tinysecurity_redact::Redactor;
//! use tinysecurity_bus::{RedactorConfig, RedactMode, RedactRequest};
//! let registry = Redactor::new(&RedactorConfig::default())?;
//! let result = registry.redact(&RedactRequest {
//!     text: "bearer private-token".into(), mode: RedactMode::Text,
//! })?;
//! assert!(!result.text.contains("private-token"));
//! # Ok::<(), tinysecurity_bus::Error>(())
//! ```
mod extended;
mod patterns;
mod prompt;
mod score;
mod structured;
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use tinysecurity_bus::{
    Error, RedactMode, RedactRequest, RedactResponse, RedactorConfig, Result, ScanPromptRequest,
    ScanPromptScoredRequest2, ScanPromptScoredResponse2, ScanResponse, ScanToolDefinitionRequest,
};

pub(crate) const MAX_INPUT: usize = 65_536;
pub(crate) const MAX_OUTPUT: usize = 131_072;
pub(crate) const MAX_DEPTH: usize = 32;
pub(crate) const MARKER: &str = "[REDACTED]";
pub use extended::ExtendedRedactors;
/// A JSON value after content sanitation, paired with a content-free change tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sanitized<T> {
    /// The sanitized value.
    pub value: T,
    /// Summary of the edits made during sanitation.
    pub report: SanitizationReport,
}
/// Counts of edits made by [`Redactor::sanitize_json`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SanitizationReport {
    /// String nodes changed by text redaction.
    pub text_redactions: usize,
    /// Object entries dropped because their key is sensitive.
    pub key_redactions: usize,
    /// Whole private-key blocks found in string values.
    pub blocked_secret_hits: usize,
    /// Subtrees replaced at the JSON traversal depth limit.
    pub depth_redactions: usize,
    /// Validated personal-identifier matches in string values.
    pub pii_redactions: usize,
}
impl SanitizationReport {
    /// Whether sanitation changed at least one value or key.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.text_redactions
            + self.key_redactions
            + self.blocked_secret_hits
            + self.depth_redactions
            + self.pii_redactions
            > 0
    }
}
/// Immutable shared matching registry; Debug intentionally exposes no patterns or secrets.
#[derive(Clone)]
pub struct Redactor(Arc<Registry>);
struct Registry {
    patterns: patterns::Patterns,
    scanner: prompt::Scanner,
    scorer: score::Scorer,
    /// The initialization literals, kept so a per-call extension can union them.
    base: RedactorConfig,
}
impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Redactor([REDACTED])")
    }
}
impl Redactor {
    /// Validate and compile initialization-only literal credentials and fixed rules.
    ///
    /// # Errors
    /// Rejects more than 128 literals, a literal outside 4..=4096 bytes, a total
    /// exceeding 16384 bytes, marker-template/count collisions or invalid built-in patterns.
    pub fn new(config: &RedactorConfig) -> Result<Self> {
        Ok(Self(Arc::new(Registry {
            patterns: patterns::Patterns::new(config)?,
            scanner: prompt::Scanner::new()?,
            scorer: score::Scorer::new()?,
            base: config.clone(),
        })))
    }
    /// Sanitize a bounded surface. Failed sanitation returns no original payload.
    ///
    /// # Errors
    /// Rejects malformed structured input/endpoints, excessive input, output or depth.
    pub fn redact(&self, request: &RedactRequest) -> Result<RedactResponse> {
        bounded(&request.text)?;
        let text = match request.mode {
            RedactMode::Endpoint | RedactMode::EndpointOrigin | RedactMode::EndpointHost => {
                self.endpoint(&request.text, &request.mode)?
            }
            RedactMode::IdentifierHash => {
                if request.text.len() == 8 && request.text.bytes().all(|b| b.is_ascii_hexdigit()) {
                    request.text.clone()
                } else {
                    let digest = Sha256::digest(request.text.as_bytes());
                    format!(
                        "{:08x}",
                        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
                    )
                }
            }
            RedactMode::LegacyMask => {
                if request.text.ends_with("***") {
                    request.text.clone()
                } else if request.text.chars().count() <= 4 {
                    "***".into()
                } else {
                    format!("{}***", request.text.chars().take(4).collect::<String>())
                }
            }
            RedactMode::CredentialsOnly => self.0.patterns.credentials(&request.text)?,
            _ => self.structured_or_text(&request.text, &request.mode, 0)?,
        };
        output_bounded(&text)?;
        Ok(RedactResponse {
            changed: text != request.text,
            text,
        })
    }
    /// Sanitize JSON content, dropping entries with credential or personal-data keys.
    /// String values are passed through the same bounded pattern registry as [`Self::redact`].
    ///
    /// # Errors
    /// Returns a content-free error if a string value exceeds the work/output bounds or
    /// contains input that cannot be safely sanitized.
    pub fn sanitize_json(&self, value: &serde_json::Value) -> Result<Sanitized<serde_json::Value>> {
        let mut report = SanitizationReport::default();
        let value = self.sanitize_json_node(value, 0, &mut report)?;
        Ok(Sanitized { value, report })
    }
    fn sanitize_json_node(
        &self,
        value: &serde_json::Value,
        depth: usize,
        report: &mut SanitizationReport,
    ) -> Result<serde_json::Value> {
        if depth > MAX_DEPTH {
            report.depth_redactions += 1;
            return Ok(serde_json::Value::String(MARKER.into()));
        }
        match value {
            serde_json::Value::Object(object) => {
                let mut clean = serde_json::Map::new();
                for (key, value) in object {
                    if crate::structured::sensitive_json_key(key) {
                        report.key_redactions += 1;
                    } else {
                        clean.insert(
                            key.clone(),
                            self.sanitize_json_node(value, depth + 1, report)?,
                        );
                    }
                }
                Ok(serde_json::Value::Object(clean))
            }
            serde_json::Value::Array(items) => items
                .iter()
                .map(|item| self.sanitize_json_node(item, depth + 1, report))
                .collect::<Result<Vec<_>>>()
                .map(serde_json::Value::Array),
            serde_json::Value::String(text) => {
                let clean = self.0.patterns.text(text)?;
                if clean != *text {
                    report.text_redactions += 1;
                    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
                        report.blocked_secret_hits += 1;
                    }
                    if clean.contains(MARKER) && text.bytes().any(|b| b.is_ascii_digit()) {
                        report.pii_redactions += 1;
                    }
                }
                Ok(serde_json::Value::String(clean))
            }
            other => Ok(other.clone()),
        }
    }
    /// Scan original prompt intent before any redaction or lexical sanitation.
    /// Results provide context and never authorize execution.
    ///
    /// # Errors
    /// Rejects input exceeding the deterministic work ceiling.
    pub fn scan_prompt(&self, request: &ScanPromptRequest) -> Result<ScanResponse> {
        bounded(&request.text)?;
        Ok(self.0.scanner.scan(&request.text))
    }
    /// Score original prompt intent: additive rule weights, a tier and the rule codes,
    /// without redaction. Results provide context and never authorize execution.
    ///
    /// # Errors
    /// Rejects input exceeding the deterministic work ceiling.
    pub fn scan_prompt_scored(
        &self,
        request: &ScanPromptScoredRequest2,
    ) -> Result<ScanPromptScoredResponse2> {
        if request.text.len() > MAX_INPUT {
            return Ok(ScanPromptScoredResponse2 {
                tier: tinysecurity_bus::PromptTier2::Review,
                score_milli: 0,
                rule_ids: vec!["input.oversized".into()],
            });
        }
        Ok(self.0.scorer.score(&request.text))
    }
    /// Scan a tool's name, keys, values and unknown metadata in the full JSON object.
    ///
    /// # Errors
    /// Rejects malformed JSON, empty/oversized names, oversized input or excessive depth.
    pub fn scan_tool_definition(
        &self,
        request: &ScanToolDefinitionRequest,
    ) -> Result<ScanResponse> {
        if request.name.is_empty() || request.name.len() > 256 {
            return Err(Error::InvalidArguments);
        }
        bounded(&request.definition_json)?;
        let value: serde_json::Value =
            serde_json::from_str(&request.definition_json).map_err(|_| Error::InvalidArguments)?;
        if !value.is_object() {
            return Err(Error::InvalidArguments);
        }
        let mut result = self.0.scanner.scan(&request.name);
        self.scan_value(&value, 0, &mut result)?;
        result.rule_ids.sort();
        result.rule_ids.dedup();
        Ok(result)
    }
    fn endpoint(&self, text: &str, mode: &RedactMode) -> Result<String> {
        if text == MARKER {
            return Ok(text.into());
        }
        let mut url = url::Url::parse(text.trim())
            .or_else(|error| {
                if text.contains("://") {
                    Err(error)
                } else {
                    url::Url::parse(&format!("https://{}", text.trim()))
                }
            })
            .map_err(|_| Error::InvalidArguments)?;
        if !matches!(
            url.scheme(),
            "http"
                | "https"
                | "ws"
                | "wss"
                | "mongodb"
                | "mongodb+srv"
                | "postgres"
                | "postgresql"
                | "mysql"
                | "redis"
                | "rediss"
        ) || url.host_str().is_none()
        {
            return Err(Error::InvalidArguments);
        }
        url.set_username("").map_err(|()| Error::InvalidArguments)?;
        url.set_password(None)
            .map_err(|()| Error::InvalidArguments)?;
        url.set_query(None);
        url.set_fragment(None);
        let out = match mode {
            RedactMode::EndpointHost => url.host_str().ok_or(Error::InvalidArguments)?.into(),
            RedactMode::EndpointOrigin => format!(
                "{}://{}",
                url.scheme(),
                &url[url::Position::BeforeHost..url::Position::AfterPort]
            ),
            _ => url.to_string().trim_end_matches('/').into(),
        };
        // Suppress sensitive retained parts instead of inserting a marker into
        // URL syntax, where reparsing could escape it and break fixed-point output.
        if self.0.patterns.retained_endpoint_is_sensitive(&out) {
            Ok(MARKER.into())
        } else {
            Ok(out)
        }
    }
}
pub(crate) fn bounded(text: &str) -> Result<()> {
    if text.len() > MAX_INPUT {
        Err(Error::InvalidArguments)
    } else {
        Ok(())
    }
}
pub(crate) fn output_bounded(text: &str) -> Result<()> {
    if text.len() > MAX_OUTPUT {
        Err(Error::InvalidArguments)
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
