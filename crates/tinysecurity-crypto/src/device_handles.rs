//! Bounded process-local device authority over the existing wire primitives.
//! Registrations and peer identity are captured only during trusted initialization.
use crate::{
    Error, Result,
    device::{KeyPair, PublicKey, Role, Tunnel},
    work_budget::{BudgetError, RateCounter, WorkBudget},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};
use tinysecurity_bus::{
    ApprovalScope2, DeviceConfig2, DeviceFrameOperation2, DeviceFrameRequest2,
    DeviceFrameResponse2, DeviceKeyPurpose2, DeviceOperation2, DeviceRequest2, DeviceResponse2,
    DeviceRole2,
};
use zeroize::Zeroizing;
/// Injected epoch and monotonic milliseconds; neither value comes from an invocation.
#[derive(Clone, Copy, Debug)]
pub struct Time {
    /// Current epoch milliseconds.
    pub wall: u64,
    /// Current monotonic milliseconds.
    pub monotonic: u64,
}
struct Scope {
    registration: ApprovalScope2,
    origin: tinysecurity_bus::Origin,
    key: Arc<KeyPair>,
    epoch: u64,
    rate: RateCounter,
}
enum Native {
    Key(Arc<KeyPair>, DeviceKeyPurpose2),
    Tunnel(Arc<Mutex<Tunnel>>, String, String),
    PairedTunnel(Arc<Mutex<Tunnel>>),
}
struct TunnelInput<'a> {
    key: &'a str,
    ephemeral: &'a str,
    peer_static: &'a str,
    peer_ephemeral: &'a str,
    role: DeviceRole2,
}
struct Entry {
    scope: String,
    epoch: u64,
    expires_wall: u64,
    expires_monotonic: u64,
    frame_rate: RateCounter,
    native: Native,
}
struct State {
    generation: u64,
    peer: String,
    scopes: BTreeMap<String, Scope>,
    handles: BTreeMap<String, Entry>,
    bootstrap: BTreeSet<(String, Vec<u8>)>,
    time: Time,
    faulted: bool,
    budget: WorkBudget,
    limits: DeviceConfig2,
}
/// Service-owned registry; dropping its last owner drops all private key material.
#[derive(Clone)]
pub struct Registry(Arc<Mutex<State>>);
const MAX_DEVICE_SCOPES: usize = 65_536;
fn ensure_scope_capacity(scope_count: usize) -> Result<()> {
    if scope_count >= MAX_DEVICE_SCOPES {
        return Err(Error::DeviceDenied);
    }
    Ok(())
}

/// Module-owned tunnel capability and its authenticated lifetime binding.
pub struct PairedTunnelRegistration<'a> {
    /// Configured scope bound to the host request.
    pub scope_id: &'a str,
    /// Opaque module-minted frame handle.
    pub handle: &'a str,
    /// Confidential tunnel state, retained only by the registry.
    pub tunnel: Arc<Mutex<Tunnel>>,
    /// Owning module generation.
    pub generation: u64,
    /// Absolute authenticated session expiry.
    pub expires_wall: u64,
    /// Monotonic authenticated session expiry.
    pub expires_monotonic: u64,
    /// Fallback clock reading for [`Registry::register_paired_tunnel`]. The
    /// clock-closure variant ignores this value and samples while holding the registry lock.
    pub now: Time,
}
impl std::fmt::Debug for PairedTunnelRegistration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairedTunnelRegistration([REDACTED])")
    }
}
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Registry([REDACTED])")
    }
}
/// An admitted bounded unit of work; dropping it releases capacity, even on cancellation.
pub struct Reservation {
    registry: Registry,
    scope: String,
    epoch: u64,
    generation: u64,
    expires_wall: u64,
    expires_monotonic: u64,
}
impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reservation([REDACTED])")
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        release_budget(&self.registry);
    }
}
struct InFlightGuard(Registry);
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        release_budget(&self.0);
    }
}
fn release_budget(registry: &Registry) {
    if let Ok(mut state) = registry.0.lock() {
        state.budget.release();
    }
}
impl Registry {
    /// Capture the actual peer and registered subjects with explicit native bounds.
    /// # Errors
    /// Rejects missing/duplicate subjects, invalid bounds, keys, clocks or entropy.
    pub fn new(
        config: DeviceConfig2,
        registrations: &[ApprovalScope2],
        peer: &str,
        generation: u64,
        now: Time,
    ) -> Result<Self> {
        let mut config = InitConfig(config);
        validate_config(&config.0)?;
        if !peer.starts_with(':') || peer.len() > 128 || generation == 0 {
            return Err(Error::DeviceDenied);
        }
        let mut scopes = BTreeMap::new();
        for scope in &mut config.0.scopes {
            let registration = registrations
                .iter()
                .find(|r| r.scope_id == scope.scope_id)
                .ok_or(Error::DeviceDenied)?;
            if registration.generation != generation
                || !registration.require_approval
                || registration.auto_approve_all
                || scope.scope_id.len() != 32
                || !scope.scope_id.bytes().all(|b| b.is_ascii_hexdigit())
                || [
                    &registration.subject.user,
                    &registration.subject.workspace,
                    &registration.subject.agent,
                ]
                .iter()
                .any(|s| s.is_empty() || s.len() > 256)
                || scopes.contains_key(&scope.scope_id)
            {
                return Err(Error::DeviceDenied);
            }
            let key = if let Some(mut secret) = scope.static_secret.take() {
                let owned = Zeroizing::new(secret);
                zeroize::Zeroize::zeroize(&mut secret);
                KeyPair::from_secret(owned)?
            } else {
                KeyPair::generate()?
            };
            scopes.insert(
                scope.scope_id.clone(),
                Scope {
                    registration: registration.clone(),
                    origin: scope.origin.clone(),
                    key: Arc::new(key),
                    epoch: 1,
                    rate: RateCounter::new(now.monotonic),
                },
            );
        }
        Ok(Self(Arc::new(Mutex::new(State {
            generation,
            peer: peer.into(),
            scopes,
            handles: BTreeMap::new(),
            bootstrap: BTreeSet::new(),
            time: now,
            faulted: false,
            budget: WorkBudget::default(),
            limits: config.0.clone(),
        }))))
    }

    /// Register one runtime scope from its canonical live approval snapshot.
    ///
    /// The caller must obtain `registration` from the approval engine; this
    /// method independently checks its generation and human-approval posture.
    /// Repeating the exact registration is idempotent. Reusing an id for a
    /// changed subject, policy, origin, or generation is denied.
    ///
    /// # Errors
    /// Rejects invalid or stale approval scopes, changed duplicate ids, full
    /// registries, unavailable clocks, and native key-generation failures.
    pub fn register_scope(
        &self,
        registration: ApprovalScope2,
        origin: tinysecurity_bus::Origin,
        generation: u64,
        now: Time,
    ) -> Result<()> {
        let mut state = self.lock()?;
        state.check_time(now)?;
        let id = &registration.scope_id;
        if generation != state.generation
            || registration.generation != generation
            || !registration.require_approval
            || registration.auto_approve_all
            || id.len() != 32
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || [
                &registration.subject.user,
                &registration.subject.workspace,
                &registration.subject.agent,
            ]
            .iter()
            .any(|value| value.is_empty() || value.len() > 256)
        {
            return Err(Error::DeviceDenied);
        }
        if let Some(existing) = state.scopes.get(id) {
            return if existing.registration == registration && existing.origin == origin {
                Ok(())
            } else {
                Err(Error::DeviceDenied)
            };
        }
        ensure_scope_capacity(state.scopes.len())?;
        let key = Arc::new(KeyPair::generate()?);
        state.scopes.insert(
            id.clone(),
            Scope {
                registration,
                origin,
                key,
                epoch: 1,
                rate: RateCounter::new(now.monotonic),
            },
        );
        Ok(())
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.0.lock().map_err(|_| Error::DeviceDenied)
    }
    fn with_clock_sample<F>(state: &mut State, sample: F) -> Result<Time>
    where
        F: FnOnce() -> Option<Time>,
    {
        let Some(now) = sample() else {
            state.fail_clock();
            return Err(Error::DeviceClock);
        };
        state.check_time(now)?;
        Ok(now)
    }
    /// Validate and reserve rate/work capacity before any callback or cryptographic work.
    /// # Errors
    /// Denies unknown scope, stale generation, rollback, expiry or exhausted bounds.
    pub fn reserve(
        &self,
        request: &DeviceRequest2,
        generation: u64,
        now: Time,
    ) -> Result<Reservation> {
        self.reserve_with_clock(request, generation, || Some(now))
    }
    /// Sample the clock while holding the registry lock, then reserve bounded work.
    ///
    /// Production adapters pass their trusted clock through this closure so a concurrently
    /// sampled older value cannot arrive after a later registry transition.
    /// # Errors
    /// Denies unavailable or rolled-back clocks and the same invalid requests as [`Self::reserve`].
    pub fn reserve_with_clock<F>(
        &self,
        request: &DeviceRequest2,
        generation: u64,
        sample: F,
    ) -> Result<Reservation>
    where
        F: FnOnce() -> Option<Time>,
    {
        let mut state = self.lock()?;
        let now = Self::with_clock_sample(&mut state, sample)?;
        state.prune(now);
        if generation != state.generation
            || request.ttl_ms == 0
            || request.ttl_ms > state.limits.max_ttl_ms
            || request.call_id.is_empty()
            || request.call_id.len() > 128
        {
            return Err(Error::DeviceDenied);
        }
        check_operation(&request.operation, state.limits.max_message_bytes)?;
        if state.budget.full(state.limits.max_in_flight) {
            return Err(Error::DeviceCapacity);
        }
        let expires_wall = now
            .wall
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(Error::DeviceDenied)?;
        let expires_monotonic = now
            .monotonic
            .checked_add(u64::from(request.ttl_ms))
            .ok_or(Error::DeviceDenied)?;
        let rate = state.limits.operations_per_minute;
        let scope = state
            .scopes
            .get_mut(&request.scope_id)
            .ok_or(Error::DeviceDenied)?;
        let epoch = scope.epoch;
        let State {
            budget,
            scopes,
            limits,
            ..
        } = &mut *state;
        budget
            .reserve(
                &mut scopes
                    .get_mut(&request.scope_id)
                    .ok_or(Error::DeviceDenied)?
                    .rate,
                now.monotonic,
                limits.max_in_flight,
                rate,
            )
            .map_err(|error| match error {
                BudgetError::Capacity => Error::DeviceCapacity,
                BudgetError::Rate => Error::DeviceRate,
            })?;
        Ok(Reservation {
            registry: self.clone(),
            scope: request.scope_id.clone(),
            epoch,
            generation,
            expires_wall,
            expires_monotonic,
        })
    }
    /// Check a reservation after an external await, before returning authority.
    /// # Errors
    /// Rejects cancelled, revoked, expired, stale or rollback-observed work.
    pub fn validate(&self, work: &Reservation, generation: u64, now: Time) -> Result<()> {
        self.validate_with_clock(work, generation, || Some(now))
    }
    /// Revalidate a reservation using a clock sampled under the registry lock.
    /// # Errors
    /// Rejects cancelled, revoked, expired, stale, unavailable-clock or rollback-observed work.
    pub fn validate_with_clock<F>(
        &self,
        work: &Reservation,
        generation: u64,
        sample: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Option<Time>,
    {
        if !Arc::ptr_eq(&self.0, &work.registry.0) {
            return Err(Error::DeviceDenied);
        }
        let mut state = self.lock()?;
        let now = Self::with_clock_sample(&mut state, sample)?;
        state.live(work, generation, now)
    }
    /// Construct the canonical, content-free approval call from immutable registration.
    /// The digest binds the original secret-bearing operation before any redaction.
    /// # Errors
    /// Rejects unknown scopes, malformed input or unavailable canonical serialization.
    pub fn approval_call(
        &self,
        request: &DeviceRequest2,
    ) -> Result<tinysecurity_bus::EvaluateRequest> {
        use sha2::{Digest, Sha256};
        let state = self.lock()?;
        check_operation(&request.operation, state.limits.max_message_bytes)?;
        let scope = state
            .scopes
            .get(&request.scope_id)
            .ok_or(Error::DeviceDenied)?;
        let original = canonical_request(request)?;
        let mut digest = Sha256::new();
        digest.update(b"tinysecurity/device-operation/v1\0");
        digest.update(state.peer.as_bytes());
        digest.update(&*original.bytes);
        let binding = format!("{:x}", digest.finalize());
        Ok(tinysecurity_bus::EvaluateRequest {
            caller: tinysecurity_bus::CallerContext {
                agent: scope.registration.subject.agent.clone(),
                call_id: format!("device-{binding}"),
                origin: scope.origin.clone(),
                tier: scope.registration.ceiling.clone(),
                ..Default::default()
            },
            call: tinysecurity_bus::ToolCall {
                tool: "device_crypto".into(),
                arguments_json: format!("{{\"operation_sha256\":\"{binding}\"}}"),
                checks: vec![tinysecurity_bus::Check::LocalDiagnostic {}],
            },
        })
    }
    /// Execute only after exact required audit and human receipts have been verified.
    /// This synchronous native boundary never holds a lock across an await.
    /// # Errors
    /// Rejects scope/purpose mismatches, invalid keys/frames, replay or exhausted capacity.
    pub fn execute(
        &self,
        work: &Reservation,
        operation: &DeviceOperation2,
        generation: u64,
        now: Time,
    ) -> Result<DeviceResponse2> {
        self.execute_with_clock(work, operation, generation, || Some(now))
    }
    /// Execute admitted work after sampling time under the registry lock.
    ///
    /// Tunnel crypto still runs after the lock is released.
    /// # Errors
    /// Rejects stale, expired, revoked, unavailable-clock or rolled-back work.
    pub fn execute_with_clock<F>(
        &self,
        work: &Reservation,
        operation: &DeviceOperation2,
        generation: u64,
        sample: F,
    ) -> Result<DeviceResponse2>
    where
        F: FnOnce() -> Option<Time>,
    {
        if !Arc::ptr_eq(&self.0, &work.registry.0) {
            return Err(Error::DeviceDenied);
        }
        let mut state = self.lock()?;
        let now = Self::with_clock_sample(&mut state, sample)?;
        state.live(work, generation, now)?;
        state.prune(now);
        check_operation(operation, state.limits.max_message_bytes)?;
        let tunnel = match operation {
            DeviceOperation2::Seal { handle, .. } | DeviceOperation2::Open { handle, .. } => {
                match &state.entry(handle, work)?.native {
                    Native::Tunnel(tunnel, _, _) => Some(Arc::clone(tunnel)),
                    Native::Key(..) | Native::PairedTunnel(..) => {
                        return Err(Error::DeviceDenied);
                    }
                }
            }
            _ => return state.execute(work, operation),
        };
        drop(state);
        let tunnel = tunnel.ok_or(Error::DeviceDenied)?;
        let mut tunnel = tunnel.lock().map_err(|_| Error::DeviceDenied)?;
        let bytes = match operation {
            DeviceOperation2::Seal { plaintext, .. } => tunnel.seal(plaintext)?,
            DeviceOperation2::Open { frame, .. } => tunnel.open(frame)?.to_vec(),
            _ => return Err(Error::DeviceDenied),
        };
        Ok(DeviceResponse2 {
            handle: None,
            public_key: None,
            bytes,
        })
    }
    /// Seal or open a frame through a tunnel handle created by an approved device operation.
    ///
    /// The opaque tunnel handle is the capability. This fast path accepts no key material and
    /// cannot create or extend a session; it checks the registered scope, live generation,
    /// expiry, revocation epoch and message bound. Each tunnel has its own rolling frame
    /// budget; it is independent of the per-scope control-operation budget. A revoked,
    /// expired or reconfigured handle is unusable immediately.
    ///
    /// # Errors
    /// Rejects an unknown or stale tunnel, malformed frame, replay, oversized payload or limit.
    pub fn execute_frame(
        &self,
        request: &DeviceFrameRequest2,
        generation: u64,
        now: Time,
    ) -> Result<DeviceFrameResponse2> {
        self.execute_frame_with_clock(request, generation, || Some(now))
    }
    /// Execute one frame after sampling time under the registry lock.
    ///
    /// The lock is released before tunnel AEAD and replay processing.
    /// # Errors
    /// Rejects an unavailable or rolled-back clock as well as invalid frame authority.
    pub fn execute_frame_with_clock<F>(
        &self,
        request: &DeviceFrameRequest2,
        generation: u64,
        sample: F,
    ) -> Result<DeviceFrameResponse2>
    where
        F: FnOnce() -> Option<Time>,
    {
        let tunnel = {
            let mut state = self.lock()?;
            let now = Self::with_clock_sample(&mut state, sample)?;
            state.prune(now);
            if generation != state.generation
                || request.scope_id.is_empty()
                || request.scope_id.len() > 128
                || request.handle.is_empty()
                || request.handle.len() > 64
                || request.call_id.is_empty()
                || request.call_id.len() > 128
            {
                return Err(Error::DeviceDenied);
            }
            let scope = state
                .scopes
                .get(&request.scope_id)
                .ok_or(Error::DeviceDenied)?;
            let entry = state
                .handles
                .get(&request.handle)
                .filter(|entry| entry.scope == request.scope_id && entry.epoch == scope.epoch)
                .ok_or(Error::DeviceDenied)?;
            let tunnel = match &entry.native {
                Native::Tunnel(tunnel, _, _) | Native::PairedTunnel(tunnel) => Arc::clone(tunnel),
                Native::Key(..) => return Err(Error::DeviceDenied),
            };
            match &request.operation {
                DeviceFrameOperation2::Seal { plaintext } => {
                    if plaintext.len() > state.limits.max_message_bytes as usize {
                        return Err(Error::Limit);
                    }
                }
                DeviceFrameOperation2::Open { frame } => {
                    if frame.len() > state.limits.max_message_bytes as usize + 41 {
                        return Err(Error::Limit);
                    }
                }
            }
            let max_in_flight = state.limits.max_in_flight;
            let max_rate = state.limits.frames_per_minute;
            let State {
                budget, handles, ..
            } = &mut *state;
            let entry = handles
                .get_mut(&request.handle)
                .filter(|entry| entry.scope == request.scope_id)
                .ok_or(Error::DeviceDenied)?;
            budget
                .reserve(
                    &mut entry.frame_rate,
                    now.monotonic,
                    max_in_flight,
                    max_rate,
                )
                .map_err(|error| match error {
                    BudgetError::Capacity => Error::DeviceCapacity,
                    BudgetError::Rate => Error::DeviceRate,
                })?;
            tunnel
        };
        self.with_frame_reservation(|| {
            tunnel
                .lock()
                .map_err(|_| Error::DeviceDenied)
                .and_then(|mut tunnel| {
                    let bytes = match &request.operation {
                        DeviceFrameOperation2::Seal { plaintext } => tunnel.seal(plaintext)?,
                        DeviceFrameOperation2::Open { frame } => tunnel.open(frame)?.to_vec(),
                    };
                    Ok(DeviceFrameResponse2 { bytes })
                })
        })
    }
    fn with_frame_reservation<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let _guard = InFlightGuard(self.clone());
        operation()
    }
    /// Revalidate a completed confidential frame before publishing its bytes.
    ///
    /// This checks that the capability stayed live while frame crypto ran outside the module's
    /// async worker. It does not spend another frame from the per-tunnel budget.
    /// # Errors
    /// Rejects changed generations, revoked or expired handles, and unavailable clocks.
    pub fn validate_frame(
        &self,
        scope_id: &str,
        handle: &str,
        generation: u64,
        now: Time,
    ) -> Result<()> {
        self.validate_frame_with_clock(scope_id, handle, generation, || Some(now))
    }
    /// Revalidate a completed frame using time sampled while holding the registry lock.
    /// # Errors
    /// Rejects an unavailable or rolled-back clock and changed or revoked tunnel authority.
    pub fn validate_frame_with_clock<F>(
        &self,
        scope_id: &str,
        handle: &str,
        generation: u64,
        sample: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Option<Time>,
    {
        let mut state = self.lock()?;
        let now = Self::with_clock_sample(&mut state, sample)?;
        state.prune(now);
        if generation != state.generation {
            return Err(Error::DeviceDenied);
        }
        let epoch = state.scopes.get(scope_id).ok_or(Error::DeviceDenied)?.epoch;
        let entry = state
            .handles
            .get(handle)
            .filter(|entry| entry.scope == scope_id && entry.epoch == epoch)
            .ok_or(Error::DeviceDenied)?;
        if !matches!(entry.native, Native::Tunnel(..) | Native::PairedTunnel(..)) {
            return Err(Error::DeviceDenied);
        }
        Ok(())
    }
    /// Register a module-verified paired session in the same opaque capability registry used by
    /// `DeviceFrame2`. The supplied tunnel remains owned by the module and is never serialized.
    /// # Errors
    /// Rejects stale generation, unknown scope, duplicate handle, invalid expiry or capacity.
    pub fn register_paired_tunnel(&self, registration: PairedTunnelRegistration<'_>) -> Result<()> {
        let now = registration.now;
        self.register_paired_tunnel_with_clock(registration, || Some(now))
    }
    /// Register a paired session while sampling trusted time under the registry lock.
    /// The registration's `now` field is ignored by this method.
    /// # Errors
    /// Rejects an unavailable or rolled-back clock and the same invalid registrations as
    /// [`Self::register_paired_tunnel`].
    pub fn register_paired_tunnel_with_clock<F>(
        &self,
        registration: PairedTunnelRegistration<'_>,
        sample: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Option<Time>,
    {
        let mut state = self.lock()?;
        let now = Self::with_clock_sample(&mut state, sample)?;
        state.prune(now);
        let epoch = state
            .scopes
            .get(registration.scope_id)
            .ok_or(Error::DeviceDenied)?
            .epoch;
        if registration.generation != state.generation
            || registration.handle.len() != 32
            || !registration
                .handle
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || state.handles.len() >= state.limits.max_handles as usize
            || state.handles.contains_key(registration.handle)
            || registration.expires_wall <= now.wall
            || registration.expires_monotonic <= now.monotonic
            || registration.expires_wall - now.wall > 604_800_000
            || registration.expires_monotonic - now.monotonic > 604_800_000
        {
            return Err(Error::DeviceDenied);
        }
        state.handles.insert(
            registration.handle.to_owned(),
            Entry {
                scope: registration.scope_id.to_owned(),
                epoch,
                expires_wall: registration.expires_wall,
                expires_monotonic: registration.expires_monotonic,
                frame_rate: RateCounter::new(now.monotonic),
                native: Native::PairedTunnel(registration.tunnel),
            },
        );
        Ok(())
    }
    /// Refresh a live paired-session entry without replacing its tunnel or frame budget.
    /// # Errors
    /// Rejects expired, stale-generation, wrong-scope or non-tunnel handles.
    pub fn refresh_paired_tunnel(
        &self,
        scope_id: &str,
        handle: &str,
        generation: u64,
        expires_wall: u64,
        expires_monotonic: u64,
        now: Time,
    ) -> Result<()> {
        self.refresh_paired_tunnel_with_clock(
            scope_id,
            handle,
            generation,
            expires_wall,
            expires_monotonic,
            || Some(now),
        )
    }
    /// Refresh a paired-session entry while sampling trusted time under the registry lock.
    /// # Errors
    /// Rejects an unavailable or rolled-back clock and the same invalid sessions as
    /// [`Self::refresh_paired_tunnel`].
    pub fn refresh_paired_tunnel_with_clock<F>(
        &self,
        scope_id: &str,
        handle: &str,
        generation: u64,
        expires_wall: u64,
        expires_monotonic: u64,
        sample: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Option<Time>,
    {
        let mut state = self.lock()?;
        let now = Self::with_clock_sample(&mut state, sample)?;
        state.prune(now);
        if generation != state.generation
            || expires_wall <= now.wall
            || expires_monotonic <= now.monotonic
            || expires_wall - now.wall > 604_800_000
            || expires_monotonic - now.monotonic > 604_800_000
        {
            return Err(Error::DeviceDenied);
        }
        let epoch = state.scopes.get(scope_id).ok_or(Error::DeviceDenied)?.epoch;
        let entry = state
            .handles
            .get_mut(handle)
            .filter(|entry| entry.scope == scope_id && entry.epoch == epoch)
            .ok_or(Error::DeviceDenied)?;
        if !matches!(entry.native, Native::PairedTunnel(..))
            || now.wall >= entry.expires_wall
            || now.monotonic >= entry.expires_monotonic
        {
            return Err(Error::DeviceDenied);
        }
        entry.expires_wall = expires_wall;
        entry.expires_monotonic = expires_monotonic;
        Ok(())
    }
    /// Immediately invalidate one opaque tunnel handle, including pending response validation.
    /// # Errors
    /// Rejects an unavailable registry; an unknown handle is already retired.
    pub fn retire_paired_tunnel(&self, handle: &str) -> Result<()> {
        let mut state = self.lock()?;
        if state
            .handles
            .get(handle)
            .is_some_and(|entry| matches!(&entry.native, Native::PairedTunnel(_)))
        {
            state.handles.remove(handle);
        }
        Ok(())
    }
    /// Wipe all paired tunnel capabilities for one authenticated scope on logout.
    /// In-flight frame responses fail their late registry validation after removal.
    /// # Errors
    /// Rejects a poisoned registry.
    pub fn retire_paired_scope(&self, scope_id: &str) -> Result<()> {
        let mut state = self.lock()?;
        state.handles.retain(|_, entry| {
            entry.scope != scope_id || !matches!(&entry.native, Native::PairedTunnel(_))
        });
        Ok(())
    }
    /// Close native authority and drop all owned credentials even if observers remain.
    /// Cleanup recovers a poisoned lock only to destroy state; it never restores authority.
    pub fn close(&self) {
        let mut state = match self.0.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.faulted = true;
        state.handles.clear();
        state.bootstrap.clear();
        state.scopes.clear();
    }
    /// Latch an unavailable clock and invalidate every outstanding handle.
    /// # Errors
    /// Rejects a poisoned registry; it cannot authorize any further work.
    pub fn fail_clock(&self) -> Result<()> {
        let mut state = self.lock()?;
        state.fail_clock();
        Ok(())
    }
    /// Return init registrations and current limits without retaining credential inputs.
    /// # Errors
    /// Rejects a poisoned native registry.
    pub fn configuration(&self) -> Result<DeviceConfig2> {
        Ok(self.lock()?.limits.clone())
    }
    /// Validate a proposed SDK configuration before publishing any new generation.
    /// # Errors
    /// Rejects changed registrations/credentials, invalid limits or stale generation.
    pub fn validate_configuration(&self, config: &DeviceConfig2, generation: u64) -> Result<()> {
        validate_config(config)?;
        let state = self.lock()?;
        if generation <= state.generation
            || config.scopes != state.limits.scopes
            || state.bootstrap.len() > config.max_bootstrap_nonces as usize
        {
            return Err(Error::DeviceDenied);
        }
        Ok(())
    }
    /// Prepare reconfiguration while excluding concurrent replay and epoch changes.
    /// Dropping the preparation leaves authority and replay evidence unchanged.
    /// # Errors
    /// Rejects invalid limits, credentials, stale generations, replay capacity or exhausted epochs.
    pub fn prepare_reconfiguration(
        &self,
        config: DeviceConfig2,
        generation: u64,
    ) -> Result<PreparedReconfiguration<'_>> {
        validate_config(&config)?;
        let state = self.lock()?;
        if generation <= state.generation
            || config
                .scopes
                .iter()
                .any(|scope| scope.static_secret.is_some())
            || config.scopes != state.limits.scopes
            || state.bootstrap.len() > config.max_bootstrap_nonces as usize
        {
            return Err(Error::DeviceDenied);
        }
        let epochs = state
            .scopes
            .iter()
            .map(|(id, scope)| {
                Ok((
                    id.clone(),
                    scope.epoch.checked_add(1).ok_or(Error::DeviceDenied)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(PreparedReconfiguration {
            state,
            config,
            generation,
            epochs,
        })
    }
    /// Advance accepted configuration, invalidating old handles without erasing replay evidence.
    /// # Errors
    /// Rejects invalid configuration, stale generation, replay capacity or exhausted epochs.
    pub fn reconfigure(&self, config: DeviceConfig2, generation: u64) -> Result<()> {
        self.prepare_reconfiguration(config, generation)?.commit();
        Ok(())
    }
}
/// An exclusively locked, fully validated configuration transition.
pub struct PreparedReconfiguration<'a> {
    state: MutexGuard<'a, State>,
    config: DeviceConfig2,
    generation: u64,
    epochs: BTreeMap<String, u64>,
}
impl std::fmt::Debug for PreparedReconfiguration<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedReconfiguration([REDACTED])")
    }
}
impl PreparedReconfiguration<'_> {
    /// Commit the prepared transition without further fallible checks.
    pub fn commit(mut self) {
        self.state.handles.clear();
        for (id, scope) in &mut self.state.scopes {
            scope.epoch = self.epochs[id];
        }
        self.state.generation = self.generation;
        self.state.limits = self.config;
    }
}
impl State {
    fn fail_clock(&mut self) {
        self.faulted = true;
        self.handles.clear();
        self.bootstrap.clear();
    }
    fn check_time(&mut self, now: Time) -> Result<()> {
        if now.wall < self.time.wall || now.monotonic < self.time.monotonic {
            self.fail_clock();
        }
        self.time = now;
        if self.faulted {
            Err(Error::DeviceClock)
        } else {
            Ok(())
        }
    }
    fn prune(&mut self, now: Time) {
        self.handles
            .retain(|_, e| now.wall < e.expires_wall && now.monotonic < e.expires_monotonic);
        let expired = self
            .handles
            .iter()
            .filter_map(|(id, entry)| match &entry.native {
                Native::Tunnel(_, key, ephemeral)
                    if !self.handles.contains_key(key) || !self.handles.contains_key(ephemeral) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for handle in expired {
            self.handles.remove(&handle);
        }
    }
    fn live(&self, work: &Reservation, generation: u64, now: Time) -> Result<()> {
        if work.generation != self.generation
            || generation != self.generation
            || now.wall >= work.expires_wall
            || now.monotonic >= work.expires_monotonic
            || self
                .scopes
                .get(&work.scope)
                .is_none_or(|s| s.epoch != work.epoch)
        {
            return Err(Error::DeviceDenied);
        }
        Ok(())
    }
    fn entry(&self, handle: &str, work: &Reservation) -> Result<&Entry> {
        self.handles
            .get(handle)
            .filter(|e| e.scope == work.scope && e.epoch == work.epoch)
            .ok_or(Error::DeviceDenied)
    }
    fn key(
        &self,
        handle: &str,
        work: &Reservation,
        purpose: DeviceKeyPurpose2,
    ) -> Result<Arc<KeyPair>> {
        match &self.entry(handle, work)?.native {
            Native::Key(key, actual) if *actual == purpose => Ok(Arc::clone(key)),
            _ => Err(Error::DeviceDenied),
        }
    }
    fn insert(&mut self, work: &Reservation, native: Native) -> Result<String> {
        if self.handles.len() >= self.limits.max_handles as usize {
            return Err(Error::DeviceCapacity);
        }
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        let hex = b"0123456789abcdef";
        let handle = bytes
            .iter()
            .flat_map(|byte| [hex[usize::from(byte >> 4)], hex[usize::from(byte & 15)]])
            .map(char::from)
            .collect::<String>();
        if self.handles.contains_key(&handle) {
            return Err(Error::DeviceDenied);
        }
        self.handles.insert(
            handle.clone(),
            Entry {
                scope: work.scope.clone(),
                epoch: work.epoch,
                expires_wall: work.expires_wall,
                expires_monotonic: work.expires_monotonic,
                frame_rate: RateCounter::new(self.time.monotonic),
                native,
            },
        );
        Ok(handle)
    }
    fn bootstrap_open(
        &mut self,
        work: &Reservation,
        handle: &str,
        frame: &[u8],
        peer: Option<&str>,
    ) -> Result<(Option<String>, Vec<u8>)> {
        let header = if peer.is_some() { 1 } else { 33 };
        if frame.len() < header + 40 {
            return Err(Error::InvalidInput);
        }
        let purpose = if peer.is_some() {
            DeviceKeyPurpose2::Ephemeral
        } else {
            DeviceKeyPurpose2::Static
        };
        let key = self.key(handle, work, purpose)?;
        let nonce = (
            format!("{}:{}", work.scope, key.public_key().encode()),
            frame[..header + 24].to_vec(),
        );
        if self.bootstrap.contains(&nonce) {
            return Err(Error::Replay);
        }
        if self.bootstrap.len() >= self.limits.max_bootstrap_nonces as usize {
            return Err(Error::DeviceCapacity);
        }
        let (public, plaintext) = if let Some(peer) = peer {
            (None, key.open_ack(PublicKey::decode(peer)?, frame)?)
        } else {
            let (public, plaintext) = key.open_handshake(frame)?;
            (Some(public.encode()), plaintext)
        };
        self.bootstrap.insert(nonce);
        Ok((public, plaintext.to_vec()))
    }
    fn issue_key(
        &mut self,
        work: &Reservation,
        purpose: DeviceKeyPurpose2,
    ) -> Result<DeviceResponse2> {
        let key = match purpose {
            DeviceKeyPurpose2::Static => Arc::clone(&self.scopes[&work.scope].key),
            DeviceKeyPurpose2::Ephemeral => Arc::new(KeyPair::generate()?),
        };
        Ok(DeviceResponse2 {
            public_key: Some(key.public_key().encode()),
            handle: Some(self.insert(work, Native::Key(key, purpose))?),
            bytes: vec![],
        })
    }
    fn create_tunnel(&mut self, work: &Reservation, input: &TunnelInput<'_>) -> Result<String> {
        let own = self.key(input.key, work, DeviceKeyPurpose2::Static)?;
        let eph = self.key(input.ephemeral, work, DeviceKeyPurpose2::Ephemeral)?;
        let peer = PublicKey::decode(input.peer_ephemeral)?;
        let (client, server, native_role) = match input.role {
            DeviceRole2::Client => (eph.public_key(), peer, Role::Client),
            DeviceRole2::Server => (peer, eph.public_key(), Role::Server),
        };
        let keys = own.session_keys(
            PublicKey::decode(input.peer_static)?,
            &eph,
            peer,
            client,
            server,
        )?;
        self.insert(
            work,
            Native::Tunnel(
                Arc::new(Mutex::new(Tunnel::new(native_role, keys))),
                input.key.to_owned(),
                input.ephemeral.to_owned(),
            ),
        )
    }
    fn execute(
        &mut self,
        work: &Reservation,
        operation: &DeviceOperation2,
    ) -> Result<DeviceResponse2> {
        use DeviceOperation2 as Op;
        let mut response = DeviceResponse2 {
            handle: None,
            public_key: None,
            bytes: vec![],
        };
        match operation {
            Op::Key { purpose } => return self.issue_key(work, *purpose),
            Op::Tunnel {
                key,
                ephemeral,
                peer_static,
                peer_ephemeral,
                role,
            } => {
                response.handle = Some(self.create_tunnel(
                    work,
                    &TunnelInput {
                        key,
                        ephemeral,
                        peer_static,
                        peer_ephemeral,
                        role: *role,
                    },
                )?);
            }
            // Tunnel frame work is dispatched by Registry::execute outside the registry lock.
            Op::Seal { .. } | Op::Open { .. } => return Err(Error::DeviceDenied),
            Op::SealHandshake {
                handle,
                peer,
                plaintext,
            } => {
                response.bytes = self
                    .key(handle, work, DeviceKeyPurpose2::Ephemeral)?
                    .seal_handshake(PublicKey::decode(peer)?, plaintext)?;
            }
            Op::SealAck {
                handle,
                peer,
                plaintext,
            } => {
                response.bytes = self
                    .key(handle, work, DeviceKeyPurpose2::Static)?
                    .seal_ack(PublicKey::decode(peer)?, plaintext)?;
            }
            Op::OpenHandshake { handle, frame } => {
                (response.public_key, response.bytes) =
                    self.bootstrap_open(work, handle, frame, None)?;
            }
            Op::OpenAck {
                handle,
                peer,
                frame,
            } => {
                (response.public_key, response.bytes) =
                    self.bootstrap_open(work, handle, frame, Some(peer))?;
            }
            Op::Revoke { handle } => {
                self.entry(handle, work)?;
                self.handles.remove(handle);
                self.handles.retain(|_, e| !matches!(&e.native, Native::Tunnel(_, a, b) if a == handle || b == handle));
                // Fence already admitted work while leaving unrelated handles usable.
                let scope = self
                    .scopes
                    .get_mut(&work.scope)
                    .ok_or(Error::DeviceDenied)?;
                scope.epoch = scope.epoch.checked_add(1).ok_or(Error::DeviceDenied)?;
                for entry in self.handles.values_mut().filter(|e| e.scope == work.scope) {
                    entry.epoch = scope.epoch;
                }
            }
            Op::Cancel => {
                let scope = self
                    .scopes
                    .get_mut(&work.scope)
                    .ok_or(Error::DeviceDenied)?;
                scope.epoch = scope.epoch.checked_add(1).ok_or(Error::DeviceDenied)?;
                self.handles.retain(|_, e| e.scope != work.scope);
                // Keep authenticated replay evidence through cancellation: an imported
                // static key must not accept an old bootstrap when a new handle is issued.
            }
        }
        Ok(response)
    }
}
fn validate_config(config: &DeviceConfig2) -> Result<()> {
    if config.scopes.len() > 128
        || !(1..=4096).contains(&config.max_handles)
        || !(1..=32).contains(&config.max_in_flight)
        || !(1..=4096).contains(&config.operations_per_minute)
        || !(1..=60_000).contains(&config.frames_per_minute)
        || !(1..=300_000).contains(&config.max_ttl_ms)
        || !(1..=1_048_576).contains(&config.max_message_bytes)
        || !(1..=4096).contains(&config.max_bootstrap_nonces)
    {
        return Err(Error::DeviceDenied);
    }
    Ok(())
}
fn check_operation(operation: &DeviceOperation2, max: u32) -> Result<()> {
    use DeviceOperation2 as Op;
    let (strings, bytes, overhead): (Vec<&str>, &[u8], usize) = match operation {
        Op::Key { .. } | Op::Cancel => (vec![], &[], 0),
        Op::Tunnel {
            key,
            ephemeral,
            peer_static,
            peer_ephemeral,
            ..
        } => (vec![key, ephemeral, peer_static, peer_ephemeral], &[], 0),
        Op::Seal { handle, plaintext } => (vec![handle], plaintext, 0),
        Op::Open { handle, frame } | Op::OpenAck { handle, frame, .. } => (vec![handle], frame, 41),
        Op::SealHandshake {
            handle,
            peer,
            plaintext,
        }
        | Op::SealAck {
            handle,
            peer,
            plaintext,
        } => (vec![handle, peer], plaintext, 0),
        Op::OpenHandshake { handle, frame } => (vec![handle], frame, 73),
        Op::Revoke { handle } => (vec![handle], &[], 0),
    };
    if strings.iter().any(|s| s.is_empty() || s.len() > 64) || bytes.len() > max as usize + overhead
    {
        return Err(Error::Limit);
    }
    if matches!(operation, Op::OpenAck { peer, .. } if peer.len() != 43) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
#[cfg(test)]
#[path = "device_handles_tests.rs"]
mod tests;

struct InitConfig(DeviceConfig2);
impl Drop for InitConfig {
    fn drop(&mut self) {
        for scope in &mut self.0.scopes {
            if let Some(secret) = &mut scope.static_secret {
                zeroize::Zeroize::zeroize(secret);
            }
        }
    }
}
/// Owned invocation payload wiped after native work or callback cancellation.
pub struct ConfidentialRequest(DeviceRequest2);
impl std::fmt::Debug for ConfidentialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfidentialRequest([REDACTED])")
    }
}
impl ConfidentialRequest {
    /// Take ownership of a decoded confidential request.
    #[must_use]
    pub fn new(request: DeviceRequest2) -> Self {
        Self(request)
    }
    /// Borrow its exact operation without duplicating private buffers.
    #[must_use]
    pub fn request(&self) -> &DeviceRequest2 {
        &self.0
    }
}
impl Drop for ConfidentialRequest {
    fn drop(&mut self) {
        use DeviceOperation2 as Op;
        match &mut self.0.operation {
            Op::Seal { plaintext, .. }
            | Op::SealHandshake { plaintext, .. }
            | Op::SealAck { plaintext, .. } => zeroize::Zeroize::zeroize(plaintext),
            Op::Open { frame, .. }
            | Op::OpenHandshake { frame, .. }
            | Op::OpenAck { frame, .. } => zeroize::Zeroize::zeroize(frame),
            _ => {}
        }
    }
}

/// Owned init configuration with cleanup on every early validation failure.
pub struct ConfidentialConfig(Option<DeviceConfig2>);
impl std::fmt::Debug for ConfidentialConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfidentialConfig([REDACTED])")
    }
}
impl ConfidentialConfig {
    /// Take ownership of an optional SDK credential configuration.
    #[must_use]
    pub fn new(config: Option<DeviceConfig2>) -> Self {
        Self(config)
    }
    /// Borrow it for validation without copying private material.
    #[must_use]
    pub fn configuration(&self) -> Option<&DeviceConfig2> {
        self.0.as_ref()
    }
    /// Move validated initialization into the native registry, which owns cleanup.
    #[must_use]
    pub fn take(&mut self) -> Option<DeviceConfig2> {
        self.0.take()
    }
}
impl Drop for ConfidentialConfig {
    fn drop(&mut self) {
        if let Some(config) = &mut self.0 {
            for scope in &mut config.scopes {
                if let Some(secret) = &mut scope.static_secret {
                    zeroize::Zeroize::zeroize(secret);
                }
            }
        }
    }
}

// Bounded staging is zeroizing before the first confidential byte is written.
// The writer refuses growth, including a future serde wire-format expansion.
struct CanonicalRequest {
    bytes: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    grew: bool,
}
impl std::io::Write for CanonicalRequest {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        if self.bytes.len() + bytes.len() > self.bytes.capacity() && !self.bytes.is_empty() {
            self.grew = true;
        }
        if bytes.len() > self.bytes.capacity() - self.bytes.len() {
            return Err(std::io::Error::other("device serialization capacity"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_request(request: &DeviceRequest2) -> Result<CanonicalRequest> {
    use DeviceOperation2 as Op;
    if request.scope_id.len() > 128 || request.call_id.len() > 128 {
        return Err(Error::Limit);
    }
    check_operation(&request.operation, 1 << 20)?;
    let bytes = match &request.operation {
        Op::Seal { plaintext, .. }
        | Op::SealHandshake { plaintext, .. }
        | Op::SealAck { plaintext, .. } => plaintext.len(),
        Op::Open { frame, .. } | Op::OpenHandshake { frame, .. } | Op::OpenAck { frame, .. } => {
            frame.len()
        }
        _ => 0,
    };
    // Each byte needs at most four JSON characters including its comma. The
    // fixed allowance covers six-character escaping of every bounded string,
    // operation tags, field names, punctuation and all integer digits.
    let capacity = bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(4096))
        .ok_or(Error::Limit)?;
    let mut writer = CanonicalRequest {
        bytes: Zeroizing::new(Vec::with_capacity(capacity)),
        #[cfg(test)]
        grew: false,
    };
    serde_json::to_writer(&mut writer, request).map_err(|_| Error::DeviceDenied)?;
    Ok(writer)
}
