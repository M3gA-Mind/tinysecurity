//! Typed native config cipher ownership; never a host-linked or bus export API.
//!
//! Preparation captures selected-master and fixed-consumer authority in the
//! original private commitment. A bounded owner table consumes each pending
//! challenge once. Cipher work is synchronous; no worker or second queue exists.
//! Admission remains owned through the fixed confidential delivery future.
use super::{
    Arc, BTreeSet, Binding, Error, MasterHandle, MasterKey, Material, Mutex, OperationKind,
    Purpose, Registry, Request, Reservation, Result, State, SubjectScope, Time, Verification,
    Zeroize, Zeroizing, constant_time, field, handle_identity, hmac, text,
};
use crate::secretstore::SecretCipher;

/// Exact config cipher operation captured in private authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    /// Encrypt a configuration value.
    Encrypt,
    /// Decrypt without changing stored bytes.
    Decrypt,
    /// Decrypt and optionally replace historical legacy encryption.
    DecryptAndMigrate,
}
/// Immutable trusted configuration; neither field is invocation authority.
pub struct CipherConfig {
    /// Fixed native consumer registration, captured at trusted initialization.
    pub consumer: String,
    /// Trusted configuration encryption setting.
    pub enabled: bool,
}
/// Exact original request from a trusted authenticated native handler.
pub struct CipherRequest<'a> {
    /// Registered original subject selected by that handler.
    pub registration: &'a str,
    /// Actual captured SDK peer.
    pub authenticated_peer: &'a str,
    /// Captured current generation.
    pub generation: u64,
    /// Original native call correlation.
    pub call_id: &'a str,
    /// Existing config-purpose native master; never returns its bytes.
    pub master: &'a MasterHandle,
    /// Exact operation, with separate immutable binding.
    pub kind: CipherKind,
    /// Original confidential input; allocated capacity is charged.
    pub input: Zeroizing<Vec<u8>>,
    /// Shortening operation lifetime.
    pub ttl_ms: u32,
}
/// Fixed native confidential delivery port captured at initialization.
///
/// This is an implementation-owner provenance boundary. Implementations must
/// deliver to their authenticated fixed destination inside this future, without
/// detached work, and acknowledge only completed delivery. Capturing an arbitrary
/// caller-provided callback is not a valid implementation. The following module
/// adapter must capture this port and the actual SDK peer at trusted init.
pub trait NativeCipherConsumer: Send + Sync {
    /// Deliver bound output and acknowledge its exact private correlation.
    fn deliver<'a>(
        &'a self,
        delivery: &'a CipherDelivery,
    ) -> Verification<'a, DeliveryAcknowledgement>;
}
struct ConfidentialText(Zeroizing<String>);
impl ConfidentialText {
    fn as_str(&self) -> &str {
        &self.0
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl Drop for ConfidentialText {
    fn drop(&mut self) {
        self.0.as_mut_str().zeroize();
        #[cfg(test)]
        tests::observe_wiped(self.0.as_bytes());
    }
}
/// Private typed output offered only to the fixed configured native consumer.
/// It cannot be obtained from a registry read/export operation or serialized.
pub struct CipherDelivery {
    plaintext: ConfidentialText,
    replacement: Option<ConfidentialText>,
    kind: CipherKind,
    call_id: String,
    registration: String,
    subject: SubjectScope,
    correlation: [u8; 32],
    output: [u8; 32],
    expires_at_ms: u64,
}
impl CipherDelivery {
    /// Borrow confidential output only inside the fixed native delivery future.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        self.plaintext.as_str()
    }
    /// Borrow the exact replacement inside the same confidential native delivery.
    /// With encryption disabled this contains plaintext, never public ciphertext.
    #[must_use]
    pub fn migration_replacement(&self) -> Option<&str> {
        self.replacement.as_ref().map(ConfidentialText::as_str)
    }
    /// Original call correlation captured by the trusted native handler.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Safe keyed original-operation correlation, distinct even for repeated call IDs.
    /// It contains no original input, subject or plain input hash.
    #[must_use]
    pub fn safe_call_id(&self) -> String {
        format!("native-{}", super::hex(&self.correlation))
    }
    /// Original immutable native registration, for this trusted delivery port only.
    #[must_use]
    pub fn registration(&self) -> &str {
        &self.registration
    }
    /// Original immutable subject captured by the registry at trusted initialization.
    /// The native adapter must compare it with its independently captured destination.
    #[must_use]
    pub fn subject(&self) -> &SubjectScope {
        &self.subject
    }
    /// Exact original operation; decrypt and migrate are different authorities.
    #[must_use]
    pub fn kind(&self) -> CipherKind {
        self.kind
    }
    /// Original shortening deadline, bounded by the selected master's lifetime.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// Keyed exact-output correlation for the fixed trusted native callback.
    /// It exposes no plaintext, raw input hash or master material.
    #[must_use]
    pub fn safe_output_id(&self) -> String {
        format!("output-{}", super::hex(&self.output))
    }
    /// Acknowledge actual completed delivery inside the fixed trusted native port.
    /// Receipt construction alone is not independent transport provenance.
    #[must_use]
    pub fn acknowledge(&self) -> DeliveryAcknowledgement {
        DeliveryAcknowledgement {
            correlation: self.correlation,
            output: self.output,
        }
    }
}
/// Move-only private acknowledgement; request strings cannot construct it.
pub struct DeliveryAcknowledgement {
    correlation: [u8; 32],
    output: [u8; 32],
}
/// Successful output classification; passthrough never returns public plaintext.
pub enum CipherResult {
    /// A true encrypted, nonempty enc2 ciphertext.
    Ciphertext(String),
    /// Confidential output reached the fixed native port.
    Delivered {
        /// True when historical legacy bytes had a replacement.
        migrated: bool,
        /// Only a true encrypted replacement; disabled replacement stays private.
        replacement_ciphertext: Option<String>,
    },
}
#[derive(Clone)]
pub(super) struct CipherBinding {
    owner: [u8; 32],
    master: [u8; 32],
    master_epoch: u64,
    master_expires: Time,
    consumer: String,
    kind: CipherKind,
    enabled: bool,
}
impl CipherBinding {
    pub(super) fn cap_deadline(&self, expires: &mut Time, now: Time) -> Result<()> {
        expires.wall = expires.wall.min(self.master_expires.wall);
        expires.monotonic = expires.monotonic.min(self.master_expires.monotonic);
        if expires.wall <= now.wall || expires.monotonic <= now.monotonic {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    pub(super) fn input_limit(&self, plaintext_limit: usize, input: &[u8]) -> usize {
        if self.kind == CipherKind::Encrypt {
            return plaintext_limit;
        }
        if input.starts_with(b"enc2:") {
            plaintext_limit
                .saturating_add(28)
                .saturating_mul(2)
                .saturating_add(5)
        } else if input.starts_with(b"enc:") {
            plaintext_limit.saturating_mul(2).saturating_add(4)
        } else {
            plaintext_limit
        }
    }
    pub(super) fn commit(&self, context: &mut hmac::Context) {
        field(context, &self.owner);
        field(context, &self.master);
        field(context, self.consumer.as_bytes());
        for number in [
            self.master_epoch,
            self.master_expires.wall,
            self.master_expires.monotonic,
            self.kind as u64,
            u64::from(self.enabled),
        ] {
            context.update(&number.to_be_bytes());
        }
    }
}
struct PendingState {
    live: Mutex<BTreeSet<[u8; 32]>>,
}
/// Real private pending operation owner; dropping it cancels exact authority.
pub struct CipherPending {
    owner: Arc<PendingState>,
    work: Option<Reservation>,
    identity: [u8; 32],
}
impl CipherPending {
    /// Borrow immutable safe binding metadata for the fixed module audit port.
    /// # Errors
    /// Rejects already consumed authority.
    pub fn binding(&self) -> Result<&Binding> {
        Ok(&self.work.as_ref().ok_or(Error::NativeDenied)?.binding)
    }
    /// Compare confidential execution input with the originally admitted bytes.
    /// No bytes or authorization receipt are exported.
    #[must_use]
    pub fn matches_input(&self, input: &[u8]) -> bool {
        self.work.as_ref().is_some_and(|work| {
            constant_time::verify_slices_are_equal(&work.binding.input, input).is_ok()
        })
    }
}
/// Completed cipher work retains bounded admission through final required audit.
/// Only explicit publication releases the safe result after another live check.
pub struct CipherCompletion<'a> {
    owner: &'a CipherOwner,
    work: Reservation,
    result: CipherResult,
    output_id: String,
}
impl CipherCompletion<'_> {
    /// Original private binding's safe metadata for the fixed final audit port.
    #[must_use]
    pub fn binding(&self) -> &Binding {
        &self.work.binding
    }
    /// Keyed exact-output identity for sanitized final audit.
    #[must_use]
    pub fn safe_output_id(&self) -> &str {
        &self.output_id
    }
    /// Validate original selected-master authority around every final await.
    /// # Errors
    /// Denies expiry, revocation, generation changes and permanent clock faults.
    pub fn validate(&self) -> Result<()> {
        self.owner.validate(&self.work)
    }
    /// Publish only the classified safe result after the final live check.
    /// # Errors
    /// Denies stale authority and drops unpublished output and retained admission.
    pub fn publish(self) -> Result<CipherResult> {
        self.validate()?;
        Ok(self.result)
    }
}
impl Drop for CipherPending {
    fn drop(&mut self) {
        if self.work.is_some() {
            match self.owner.live.lock() {
                Ok(mut pending) => {
                    pending.remove(&self.identity);
                }
                Err(poisoned) => {
                    poisoned.into_inner().remove(&self.identity);
                }
            }
        }
    }
}
/// Fixed native cipher owner over an existing registry.
/// Initialization does not grant authority or extend a master's lifetime.
pub struct CipherOwner {
    registry: Registry,
    config: CipherConfig,
    consumer: Arc<dyn NativeCipherConsumer>,
    identity: [u8; 32],
    pending: Arc<PendingState>,
}
/// Module-internal persistent-state cipher retained from a live `HumanOnly` master.
/// It never crosses a bus boundary and is fenced by registration epoch and module
/// generation, while the original alias expiry continues to govern only unlock.
pub struct DevicePairingStateCipher {
    key: Zeroizing<[u8; 32]>,
    registry: Registry,
    registration: String,
    scope_id: String,
    persistence_backend_id: String,
    generation: u64,
    epoch: u64,
}
impl std::fmt::Debug for DevicePairingStateCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DevicePairingStateCipher([REDACTED])")
    }
}
impl DevicePairingStateCipher {
    /// Check the immutable pairing slot binding without exposing master material.
    #[must_use]
    pub fn is_bound_to(
        &self,
        registration: &str,
        scope_id: &str,
        persistence_backend_id: &str,
        generation: u64,
    ) -> bool {
        self.registration == registration
            && self.scope_id == scope_id
            && self.persistence_backend_id == persistence_backend_id
            && self.generation == generation
    }
    fn validate(&self) -> Result<()> {
        let (state, _) = self.registry.checked_lock()?;
        if state.closed
            || state.generation != self.generation
            || state
                .scopes
                .get(&self.registration)
                .is_none_or(|scope| scope.epoch != self.epoch)
        {
            return Err(Error::NativeDenied);
        }
        Ok(())
    }
    /// Encrypt a module-owned persistent record using the existing enc2 format.
    /// # Errors
    /// Denies stale generation/registration authority and oversized values.
    pub fn encrypt(&self, plaintext: &str) -> Result<Zeroizing<String>> {
        self.validate()?;
        SecretCipher::new(Zeroizing::new(*self.key), true).encrypt_confidential(plaintext)
    }
    /// Decrypt an internal persistent record without exposing plaintext to a host callback.
    /// # Errors
    /// Denies stale generation/registration authority and invalid ciphertext.
    pub fn decrypt(&self, ciphertext: &str) -> Result<Zeroizing<String>> {
        self.validate()?;
        if !ciphertext.starts_with("enc2:") {
            return Err(Error::NativeDenied);
        }
        SecretCipher::new(Zeroizing::new(*self.key), true).decrypt(ciphertext)
    }

    /// Decrypt one historical `enc:` value for an explicit migration path.
    /// The caller must immediately re-encrypt the plaintext with [`Self::encrypt`].
    /// # Errors
    /// Denies stale authority, malformed legacy ciphertext, or non-UTF-8 plaintext.
    pub fn decrypt_legacy(&self, ciphertext: &str) -> Result<Zeroizing<String>> {
        self.validate()?;
        if !ciphertext.starts_with("enc:") {
            return Err(Error::NativeDenied);
        }
        let bytes = tinystoragedrivers::secrets::crypto::decrypt_legacy_enc(&self.key, ciphertext)
            .map_err(|_| Error::NativeDenied)?;
        String::from_utf8(bytes.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| Error::NativeDenied)
    }
}
impl CipherOwner {
    /// Capture immutable native configuration and fixed consumer.
    /// # Errors
    /// Rejects malformed configuration, entropy failure or closed authority.
    pub fn new(
        registry: Registry,
        config: CipherConfig,
        consumer: Arc<dyn NativeCipherConsumer>,
    ) -> Result<Self> {
        if !text(&config.consumer) {
            return Err(Error::NativeDenied);
        }
        drop(registry.checked_lock()?);
        let mut identity = [0; 32];
        getrandom::fill(&mut identity).map_err(|_| Error::Entropy)?;
        Ok(Self {
            registry,
            config,
            consumer,
            identity,
            pending: Arc::new(PendingState {
                live: Mutex::new(BTreeSet::new()),
            }),
        })
    }
    /// Reserve exact selected-master work in the bounded private pending owner.
    /// Keyed, non-secret fingerprint of the config master a request selects. The
    /// module compares fingerprints to refuse two live cipher registrations on one
    /// master; the master itself is never returned, stored or logged.
    /// # Errors
    /// Denies a stale, foreign or non-config master for this registration.
    pub fn master_fingerprint(
        &self,
        registration: &str,
        master: &MasterHandle,
        generation: u64,
    ) -> Result<[u8; 32]> {
        let (state, _now) = self.registry.checked_lock()?;
        let identity = handle_identity(&state.authorization_key, &master.bytes);
        let entry = state.entries.get(&identity).ok_or(Error::NativeDenied)?;
        if master.kind != OperationKind::NativeMasterGrant
            || entry.kind != OperationKind::NativeMasterGrant
            || entry.registration != registration
            || entry.purpose != Purpose::ConfigUserMaster
            || entry.generation != generation
            || state.generation != generation
        {
            return Err(Error::NativeDenied);
        }
        let Material::Master(key) = &entry.material else {
            return Err(Error::NativeDenied);
        };
        let key = hmac::Key::new(hmac::HMAC_SHA256, key.bytes());
        let mut context = hmac::Context::with_key(&key);
        context.update(b"tinysecurity/master-fingerprint/v1\0");
        let mut output = [0; 32];
        output.copy_from_slice(context.sign().as_ref());
        Ok(output)
    }
    /// # Errors
    /// Denies missing, expired, substituted or exhausted authority and oversized input.
    pub fn prepare(&self, request: CipherRequest<'_>) -> Result<CipherPending> {
        let (now, binding) = {
            let (state, now) = self.registry.checked_lock()?;
            let identity = handle_identity(&state.authorization_key, &request.master.bytes);
            let entry = state.entries.get(&identity).ok_or(Error::NativeDenied)?;
            if request.authenticated_peer != state.peer
                || request.generation != state.generation
                || request.master.kind != OperationKind::NativeMasterGrant
                || entry.kind != OperationKind::NativeMasterGrant
                || entry.registration != request.registration
                || entry.purpose != Purpose::ConfigUserMaster
                || entry.generation != request.generation
                || state
                    .scopes
                    .get(request.registration)
                    .is_none_or(|scope| scope.epoch != entry.epoch)
                || !matches!(entry.material, Material::Master(_))
            {
                return Err(Error::NativeDenied);
            }
            (
                now,
                CipherBinding {
                    owner: self.identity,
                    master: identity,
                    master_epoch: entry.epoch,
                    master_expires: entry.expires,
                    consumer: self.config.consumer.clone(),
                    kind: request.kind,
                    enabled: self.config.enabled,
                },
            )
        };
        // Both clocks must preserve the master's lifetime. No rounding or renewal.
        let remaining = binding.master_expires.wall.saturating_sub(now.wall).min(
            binding
                .master_expires
                .monotonic
                .saturating_sub(now.monotonic),
        );
        let ttl_ms = u32::try_from(remaining.min(u64::from(request.ttl_ms)))
            .map_err(|_| Error::NativeDenied)?;
        let mut work = self.registry.reserve_internal(
            Request {
                registration: request.registration,
                authenticated_peer: request.authenticated_peer,
                generation: request.generation,
                call_id: request.call_id,
                purpose: Purpose::ConfigUserMaster,
                kind: OperationKind::ConfigCipher,
                input: request.input,
                ttl_ms,
            },
            Some(binding),
            false,
            None,
        )?;
        // Charge conservative simultaneous primitive scratch and outputs before
        // running the driver. Output backing capacity is verified against this
        // charge without shrinking or reallocating confidential buffers.
        let plaintext = decoded_limit(&work.binding.input, request.kind);
        let scratch = plaintext
            .checked_mul(8)
            .and_then(|n| n.checked_add(256))
            .ok_or(Error::NativeCapacity)?;
        self.charge(&mut work, scratch)?;
        self.validate(&work)?;
        let mut live = self.pending.live.lock().map_err(|_| Error::NativeDenied)?;
        if !live.insert(work.binding.commitment) {
            return Err(Error::NativeDenied);
        }
        drop(live);
        let identity = work.binding.commitment;
        Ok(CipherPending {
            owner: self.pending.clone(),
            work: Some(work),
            identity,
        })
    }
    fn charge(&self, work: &mut Reservation, bytes: usize) -> Result<()> {
        let (mut state, now) = self.registry.checked_lock()?;
        state.live(&self.registry, work, now)?;
        let pending = state
            .pending_bytes
            .checked_add(bytes)
            .ok_or(Error::NativeCapacity)?;
        if pending > state.limits.max_pending_bytes
            || pending
                .checked_add(state.retained_bytes)
                .and_then(|n| n.checked_add(32))
                .is_none_or(|n| n > state.limits.max_resident_bytes)
        {
            return Err(Error::NativeCapacity);
        }
        work.extra_bytes = work
            .extra_bytes
            .checked_add(bytes)
            .ok_or(Error::NativeCapacity)?;
        state.pending_bytes = pending;
        Ok(())
    }
    fn validate_locked<'a>(
        &self,
        state: &'a State,
        work: &Reservation,
        now: Time,
    ) -> Result<&'a MasterKey> {
        state.live(&self.registry, work, now)?;
        let cipher = work.binding.cipher.as_ref().ok_or(Error::NativeDenied)?;
        let entry = state
            .entries
            .get(&cipher.master)
            .ok_or(Error::NativeDenied)?;
        if cipher.owner != self.identity
            || cipher.consumer != self.config.consumer
            || cipher.enabled != self.config.enabled
            || work.binding.kind != OperationKind::ConfigCipher
            || work.binding.purpose != Purpose::ConfigUserMaster
            || work.binding.peer != state.peer
            || entry.registration != work.binding.registration
            || entry.purpose != work.binding.purpose
            || entry.kind != OperationKind::NativeMasterGrant
            || entry.generation != work.binding.generation
            || entry.epoch != work.binding.epoch
            || entry.epoch != cipher.master_epoch
            || entry.expires.wall != cipher.master_expires.wall
            || entry.expires.monotonic != cipher.master_expires.monotonic
            || now.wall >= entry.expires.wall
            || now.monotonic >= entry.expires.monotonic
            || work.binding.expires.wall > entry.expires.wall
            || work.binding.expires.monotonic > entry.expires.monotonic
        {
            return Err(Error::NativeDenied);
        }
        match &entry.material {
            Material::Master(master) => Ok(master),
            _ => Err(Error::NativeDenied),
        }
    }
    fn validate(&self, work: &Reservation) -> Result<()> {
        let (state, now) = self.registry.checked_lock()?;
        self.validate_locked(&state, work, now)?;
        Ok(())
    }
    fn consume(&self, mut pending: CipherPending) -> Result<Reservation> {
        if !Arc::ptr_eq(&self.pending, &pending.owner) {
            return Err(Error::NativeDenied);
        }
        let work = pending.work.as_ref().ok_or(Error::NativeDenied)?;
        self.validate(work)?;
        if !self
            .pending
            .live
            .lock()
            .map_err(|_| Error::NativeDenied)?
            .remove(&pending.identity)
        {
            return Err(Error::NativeDenied);
        }
        pending.work.take().ok_or(Error::NativeDenied)
    }
    /// Check admitted pending authority without consuming or renewing it.
    /// # Errors
    /// Denies cross-owner, canceled, expired, revoked or substituted authority.
    pub fn validate_pending(&self, pending: &CipherPending) -> Result<()> {
        if !Arc::ptr_eq(&self.pending, &pending.owner) {
            return Err(Error::NativeDenied);
        }
        self.validate(pending.work.as_ref().ok_or(Error::NativeDenied)?)
    }
    /// Retain the selected master for one module-owned persistence identity.
    /// The returned cipher survives alias expiry but is fenced by generation,
    /// registration epoch, registry shutdown and owner drop.
    /// # Errors
    /// Denies disabled encryption, stale authority or non-encryption reservations.
    pub fn retain_device_pairing_state(
        &self,
        pending: CipherPending,
        scope_id: &str,
        persistence_backend_id: &str,
    ) -> Result<DevicePairingStateCipher> {
        if !self.config.enabled {
            return Err(Error::NativeDenied);
        }
        if scope_id.is_empty()
            || scope_id.len() > 128
            || persistence_backend_id.is_empty()
            || persistence_backend_id.len() > 128
        {
            return Err(Error::NativeDenied);
        }
        let work = self.consume(pending)?;
        let binding = work.binding.cipher.as_ref().ok_or(Error::NativeDenied)?;
        if binding.kind != CipherKind::Encrypt || !binding.enabled {
            return Err(Error::NativeDenied);
        }
        let (key, epoch) = {
            let (state, now) = self.registry.checked_lock()?;
            let key = self.validate_locked(&state, &work, now)?;
            (Zeroizing::new(*key.bytes()), binding.master_epoch)
        };
        Ok(DevicePairingStateCipher {
            key,
            registry: self.registry.clone(),
            registration: work.binding.registration.clone(),
            scope_id: scope_id.into(),
            persistence_backend_id: persistence_backend_id.into(),
            generation: work.binding.generation,
            epoch,
        })
    }
    /// Consume pending authority once and synchronously execute before delivery.
    /// No lock spans delivery; the original reservation remains owned throughout.
    /// # Errors
    /// Denies stale pending, invalid ciphertext, capacity and unacknowledged delivery.
    pub async fn execute(&self, pending: CipherPending) -> Result<CipherResult> {
        self.execute_guarded(pending).await?.publish()
    }
    /// Execute while retaining original admission through the module's final audit.
    /// # Errors
    /// Denies stale pending, invalid ciphertext, capacity and unacknowledged delivery.
    pub async fn execute_guarded(&self, pending: CipherPending) -> Result<CipherCompletion<'_>> {
        let work = self.consume(pending)?;
        let binding = work.binding.cipher.as_ref().ok_or(Error::NativeDenied)?;
        let (plain, replacement) = {
            let (state, now) = self.registry.checked_lock()?;
            let master = self.validate_locked(&state, &work, now)?;
            // Bounded synchronous work remains under the owner lock, preventing
            // concurrent revocation between the live check and cipher dispatch.
            let cipher = SecretCipher::new(Zeroizing::new(*master.bytes()), binding.enabled);
            let input =
                std::str::from_utf8(&work.binding.input).map_err(|_| Error::SecretInvalid)?;
            match binding.kind {
                CipherKind::Encrypt => (cipher.encrypt_confidential(input)?, None),
                CipherKind::Decrypt => (cipher.decrypt(input)?, None),
                CipherKind::DecryptAndMigrate => cipher.migrate_confidential(input)?,
            }
        };
        let plaintext = ConfidentialText(plain);
        let replacement = replacement.map(ConfidentialText);
        let output_capacity = plaintext
            .capacity()
            .checked_add(replacement.as_ref().map_or(0, ConfidentialText::capacity))
            .ok_or(Error::NativeCapacity)?;
        if output_capacity > work.extra_bytes {
            return Err(Error::NativeCapacity);
        }
        self.validate(&work)?;
        let output = {
            let (state, now) = self.registry.checked_lock()?;
            self.validate_locked(&state, &work, now)?;
            output_commitment(
                &state.authorization_key,
                &work.binding,
                &plaintext,
                replacement.as_ref(),
            )
        };
        let output_id = format!("output-{}", super::hex(&output));
        if binding.kind == CipherKind::Encrypt && binding.enabled && !work.binding.input.is_empty()
        {
            let ciphertext = plaintext.as_str().to_owned();
            self.validate(&work)?;
            return Ok(CipherCompletion {
                owner: self,
                work,
                output_id,
                result: CipherResult::Ciphertext(ciphertext),
            });
        }
        let delivery = CipherDelivery {
            plaintext,
            replacement,
            kind: binding.kind,
            call_id: work.binding.call_id.clone(),
            registration: work.binding.registration.clone(),
            subject: work.binding.subject.clone(),
            correlation: work.binding.commitment,
            output,
            expires_at_ms: work.binding.expires.wall,
        };
        self.validate(&work)?;
        let delivered = self.consumer.deliver(&delivery).await;
        // A failed port still crossed an await: sample true clock faults and
        // live revocation before propagating its content-free failure.
        self.validate(&work)?;
        let acknowledgement = delivered?;
        if constant_time::verify_slices_are_equal(
            &acknowledgement.correlation,
            &delivery.correlation,
        )
        .is_err()
            || constant_time::verify_slices_are_equal(&acknowledgement.output, &delivery.output)
                .is_err()
        {
            return Err(Error::NativeDenied);
        }
        let replacement_ciphertext = if binding.enabled {
            delivery
                .replacement
                .as_ref()
                .filter(|value| !value.as_str().is_empty())
                .map(|value| value.as_str().to_owned())
        } else {
            None
        };
        self.validate(&work)?;
        Ok(CipherCompletion {
            owner: self,
            work,
            output_id,
            result: CipherResult::Delivered {
                migrated: delivery.replacement.is_some(),
                replacement_ciphertext,
            },
        })
    }
}
fn decoded_limit(input: &[u8], kind: CipherKind) -> usize {
    if kind == CipherKind::Encrypt {
        return input.len();
    }
    // Includes enc2 authentication overhead in the conservative scratch charge.
    if input.starts_with(b"enc2:") {
        input.len().saturating_sub(5) / 2
    } else if input.starts_with(b"enc:") {
        input.len().saturating_sub(4) / 2
    } else {
        input.len()
    }
}
fn output_commitment(
    key: &[u8],
    binding: &Binding,
    plain: &ConfidentialText,
    replacement: Option<&ConfidentialText>,
) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut context = hmac::Context::with_key(&key);
    context.update(b"tinysecurity/config-cipher-output/v1\0");
    field(&mut context, &binding.commitment);
    field(&mut context, plain.as_str().as_bytes());
    context.update(&[u8::from(replacement.is_some())]);
    if let Some(replacement) = replacement {
        field(&mut context, replacement.as_str().as_bytes());
    }
    let mut output = [0; 32];
    output.copy_from_slice(context.sign().as_ref());
    output
}
redacted!(
    CipherConfig,
    CipherRequest<'_>,
    CipherDelivery,
    DeliveryAcknowledgement,
    CipherResult,
    CipherPending,
    CipherOwner,
    CipherCompletion<'_>
);

#[cfg(test)]
#[path = "cipher_tests.rs"]
mod tests;
