//! Audit stream pins of runtime subjects, shared by every runtime registration table.
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::RwLock,
    time::Duration,
    time::Instant,
};
use tinysecurity::approval::{Error, Result};
use tinysecurity_bus::SubjectScope;

/// Most live or recently released runtime subjects whose stream is remembered.
const MAX_PINNED_STREAMS: usize = 1 << 20;
/// How long a released subject keeps its stream: well past any callback deadline.
const STREAM_PIN_TTL: Duration = Duration::from_secs(3600);

/// A path that holds a subject's stream. A pin is released only when every holder
/// has let go, so one path retiring a subject never frees a stream another live
/// path still writes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Owner {
    /// A live approval scope that admitted the subject.
    Approval,
    /// A live sandbox scope that registered the subject.
    Sandbox,
    /// Host-recorded or cipher audit. These never release their pin.
    Recorded,
}

type StreamKey = (String, String, String);
struct StreamPin {
    stream: String,
    released: Option<Instant>,
    holders: BTreeSet<Owner>,
}

/// The audit stream of each runtime subject. A live subject always keeps its stream,
/// and a released one keeps it for `ttl` (far beyond any callback deadline), so a
/// call still in flight for a retired scope cannot land in another scope's ledger
/// when the subject registers again. Pins of subjects released longer ago are
/// reclaimed, so only live and recently retired subjects count against `max`.
pub(crate) struct StreamPins {
    streams: RwLock<BTreeMap<StreamKey, StreamPin>>,
    pub(crate) ttl: Duration,
    pub(crate) max: usize,
}
impl Default for StreamPins {
    fn default() -> Self {
        Self {
            streams: RwLock::new(BTreeMap::new()),
            ttl: STREAM_PIN_TTL,
            max: MAX_PINNED_STREAMS,
        }
    }
}
impl StreamPins {
    fn key(subject: &SubjectScope) -> StreamKey {
        (
            subject.user.clone(),
            subject.workspace.clone(),
            subject.agent.clone(),
        )
    }
    /// Pin a subject's stream for `owner` while it is live or recently released;
    /// refuse any other stream for it until the pin has been released for `ttl`.
    pub(crate) fn pin_for(&self, subject: &SubjectScope, stream_id: &str, owner: Owner) -> Result<()> {
        if stream_id.len() != 32 || !stream_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid);
        }
        let key = Self::key(subject);
        let now = Instant::now();
        let ttl = self.ttl;
        let expired = |pin: &StreamPin| {
            pin.released
                .is_some_and(|at| now.saturating_duration_since(at) >= ttl)
        };
        let mut streams = self.streams.write().map_err(|_| Error::Unavailable)?;
        if let Some(pin) = streams.get_mut(&key) {
            if pin.stream == stream_id {
                pin.released = None;
                pin.holders.insert(owner);
                return Ok(());
            }
            if !expired(pin) {
                return Err(Error::Conflict);
            }
        } else if streams.len() >= self.max {
            streams.retain(|_, pin| !expired(pin));
            if streams.len() >= self.max {
                return Err(Error::Unavailable);
            }
        }
        streams.insert(
            key,
            StreamPin {
                stream: stream_id.into(),
                released: None,
                holders: BTreeSet::from([owner]),
            },
        );
        Ok(())
    }
    /// Withdraw `owner`'s hold. The retention clock starts only when no holder is
    /// left, so a release by one path keeps the stream for every other live path.
    pub(crate) fn unpin_for(&self, subject: &SubjectScope, owner: Owner) -> Result<()> {
        if let Some(pin) = self
            .streams
            .write()
            .map_err(|_| Error::Unavailable)?
            .get_mut(&Self::key(subject))
        {
            pin.holders.remove(&owner);
            if pin.holders.is_empty() && pin.released.is_none() {
                pin.released = Some(Instant::now());
            }
        }
        Ok(())
    }
    /// Single-holder pin for the table's own tests.
    #[cfg(test)]
    pub(crate) fn pin(&self, subject: &SubjectScope, stream_id: &str) -> Result<()> {
        self.pin_for(subject, stream_id, Owner::Recorded)
    }
    /// Single-holder release for the table's own tests.
    #[cfg(test)]
    pub(crate) fn unpin(&self, subject: &SubjectScope) -> Result<()> {
        self.unpin_for(subject, Owner::Recorded)
    }
}

#[cfg(test)]
#[path = "stream_pins_tests.rs"]
mod tests;
