//! Scored prompt screening (contract 1.22).
//!
//! `ScanPrompt` answers a coarse verdict. `ScanPrompt2` answers what a host needs to
//! decide how much friction a prompt deserves: an additive score in thousandths, the
//! `Allow`, `Review` or `Block` tier it falls in and the content-free rule codes that
//! contributed, in detection order. The module owns the rules, the weights and the
//! thresholds; the host only maps a tier to its own handling. A tier is context and
//! never authorizes execution. Inputs above the 64 KiB scorer ceiling receive
//! `Review` with `input.oversized` and a zero score, so callers fail closed
//! without attempting a partial scan.
use serde::{Deserialize, Serialize};

/// Score at or above which a prompt is `Review`, in thousandths.
pub const PROMPT_REVIEW_THRESHOLD_MILLI2: u16 = 550;
/// Score at or above which a prompt is `Block`, in thousandths.
pub const PROMPT_BLOCK_THRESHOLD_MILLI2: u16 = 700;
/// Highest score, in thousandths.
pub const PROMPT_MAX_SCORE_MILLI2: u16 = 1000;

/// How much friction a prompt deserves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PromptTier2 {
    /// Nothing worth friction.
    Allow,
    /// Suspicious; a host holds it for review.
    Review,
    /// Strong injection signal; a host refuses it.
    Block,
}

impl PromptTier2 {
    /// The tier a score falls in.
    #[must_use]
    pub const fn from_score_milli(score_milli: u16) -> Self {
        if score_milli >= PROMPT_BLOCK_THRESHOLD_MILLI2 {
            Self::Block
        } else if score_milli >= PROMPT_REVIEW_THRESHOLD_MILLI2 {
            Self::Review
        } else {
            Self::Allow
        }
    }
}

/// `ScanPrompt2` payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPromptScoredRequest2 {
    /// Original prompt or untrusted content, scanned before any redaction.
    pub text: String,
}

/// `ScanPrompt2` result; content-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPromptScoredResponse2 {
    /// Tier of the score.
    pub tier: PromptTier2,
    /// Additive score in thousandths, capped at 1000.
    pub score_milli: u16,
    /// Content-free codes of the rules that fired, in detection order.
    pub rule_ids: Vec<String>,
}

impl std::fmt::Debug for ScanPromptScoredRequest2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScanPromptScoredRequest2([REDACTED])")
    }
}

#[cfg(test)]
#[path = "prompt_score_tests.rs"]
mod tests;
