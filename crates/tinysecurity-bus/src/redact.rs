//! Redaction and contextual semantic scan wire types.
use serde::{Deserialize, Serialize};
/// `RedactMode` vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactMode {
    /// Text state.
    Text,
    /// `StructuredArguments` state.
    StructuredArguments,
    /// Endpoint state.
    Endpoint,
    /// `HomePath` state.
    HomePath,
    /// Endpoint scheme and authority, excluding path and credentials.
    EndpointOrigin,
    /// Endpoint hostname only (ports excluded).
    EndpointHost,
    /// Recursive credential-key logging markers, retaining ordinary content.
    StructuredLogArguments,
    /// Browser result with only a typed confirmation UUID exempted.
    BrowserResult,
    /// SHA-256 first eight hexadecimal digits; existing eight-hex outputs are fixed points.
    IdentifierHash,
    /// Historical first-four-character mask; existing masks are fixed points.
    LegacyMask,
    /// Credentials only, for free-form tool output: the exact registry, provider
    /// token shapes, JWTs, private keys, cookie headers and labelled values that
    /// look like a credential. Contact data, URLs and paths are retained, and a
    /// labelled value that reads as source code is not rewritten.
    CredentialsOnly,
}
/// `ScanVerdict` vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanVerdict {
    /// Clean state.
    Clean,
    /// Suspicious state.
    Suspicious,
    /// Blocked state.
    Blocked,
}
/// `RedactRequest` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactRequest {
    /// Sensitive input.
    pub text: String,
    /// Redaction surface.
    pub mode: RedactMode,
}
/// `RedactWithRequest` payload (contract 1.16): a [`RedactRequest`] plus exact
/// credentials that apply to this call only.
///
/// The extra literals supplement, never replace, the initialization registry:
/// one trusted host serving many tenants redacts each tenant's own credential
/// without a process-wide reinitialization. They are bounded like the init
/// registry (at most 128 literals of 4..=4096 bytes, 16384 bytes in all) and
/// never echoed; `Debug` shows only [`crate::Secret`]'s redacted form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactWithRequest {
    /// Sensitive input.
    pub text: String,
    /// Redaction surface.
    pub mode: RedactMode,
    /// Exact credentials for this call.
    pub secrets: Vec<crate::Secret>,
}
/// `RedactResponse` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactResponse {
    /// Sanitized output.
    pub text: String,
    /// Whether substitutions occurred.
    pub changed: bool,
}
/// `ScanPromptRequest` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPromptRequest {
    /// Prompt to scan.
    pub text: String,
}
/// `ScanToolDefinitionRequest` payload. `definition_json` must serialize the
/// complete tool definition as a JSON object (including schema and metadata);
/// an MCP registry caller builds that object before making the bus call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanToolDefinitionRequest {
    /// Tool identity.
    pub name: String,
    /// Complete tool definition encoded as a JSON object, built by the caller.
    pub definition_json: String,
}
/// `ScanResponse` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanResponse {
    /// Typed scan result.
    pub verdict: ScanVerdict,
    /// Content-free matching rule identifiers.
    pub rule_ids: Vec<String>,
}
/// Initialization-only exact credential registry; never an invocation payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactorConfig {
    /// Literal credentials supplied over trusted SDK initialization only.
    pub secrets: Vec<crate::Secret>,
}
impl RedactorConfig {
    /// Whether no exact credentials supplement the built-in patterns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}
