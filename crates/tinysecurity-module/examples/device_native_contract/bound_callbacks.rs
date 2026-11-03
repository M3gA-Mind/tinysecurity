//! Host callback adapters for the device native verifier.
pub(crate) use super::fixture::store;

pub(crate) fn audit(sequence: u64) -> tinysecurity_bus::AuditCorrelation2 {
    super::fixture::audit(sequence)
}

#[path = "../approval_native_contract/bound_callback.rs"]
pub(crate) mod callback;
