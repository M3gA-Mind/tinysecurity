//! Fixed local failures without transport diagnostics or secrets.
/// Native judge failures; never include provider error payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid trusted initialization or request preparation.
    #[error("invalid judge configuration")]
    Invalid,
    /// Shared reservation or monotonic clock unavailable.
    #[error("judge budget unavailable")]
    Budget,
    /// Response failed local validation.
    #[error("invalid judge response")]
    Response,
    /// Total request deadline elapsed.
    #[error("judge deadline elapsed")]
    Timeout,
    /// Transport or provider unavailable.
    #[error("judge unavailable")]
    Unavailable,
    /// The endpoint rejected the credential.
    #[error("judge credential rejected")]
    Rejected,
}
/// Native judge result with a sanitized local error.
pub type Result<T> = std::result::Result<T, Error>;
