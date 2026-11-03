//! Native immutable scoped privacy and URL policy. Hosts link only the bus contract.
mod privacy;
mod privacy_check;
pub use privacy_check::privacy_verdict;
mod local_provider;
pub use local_provider::classify_provider_endpoint;
mod registry;
mod resolver;
mod url_guard;
pub use registry::{EgressPolicyRegistry, RegisteredEgressPolicy};
pub use resolver::{EgressClock, ResolveFailure, Resolver, SystemResolver};
#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;
