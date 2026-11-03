//! Internal cryptographic engines; hosts link only `tinysecurity-bus`.
//!
//! Password operations preserve the legacy Argon2id/AES-256-GCM payload.
//! Keys stay native and are never included in diagnostic representations.
//! Driver-backed keyring, native-handle and secret-store APIs are enabled by
//! the default `native-storage` feature. The `device-pairing` feature exposes
//! the wire crypto and pairing owner without pulling in a storage driver.
//!
//! ```
//! use tinysecurity_crypto::password::PasswordKey;
//! let salt = PasswordKey::generate_salt()?;
//! let key = PasswordKey::derive("fixture password", &salt)?;
//! let encrypted = key.encrypt(b"fixture bytes")?;
//! assert_eq!(&*key.decrypt(&encrypted)?, b"fixture bytes");
//! # Ok::<(), tinysecurity_crypto::Error>(())
//! ```
pub mod device;
pub mod device_handles;
pub mod device_pairing;
mod error;
#[cfg(feature = "native-storage")]
pub mod keyring;
#[cfg(feature = "native-storage")]
pub mod native_handles;
#[cfg(feature = "native-storage")]
pub mod native_store;
#[cfg(feature = "native-storage")]
pub mod pairing;
pub mod password;
#[cfg(feature = "native-storage")]
pub mod secretstore;
pub use error::{Error, Result};

mod work_budget;
