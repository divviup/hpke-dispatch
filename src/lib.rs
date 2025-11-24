#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    nonstandard_style,
    unused_qualifications
)]
#![warn(missing_docs, clippy::cargo)]
#![allow(
    clippy::missing_errors_doc,
    clippy::use_self,
    clippy::multiple_crate_versions
)]
#![doc = include_str!("../README.md")]

use hpke::{Deserializable, HpkeError};

mod base_mode_open;
pub use base_mode_open::base_mode_open;

mod base_mode_seal;
pub use base_mode_seal::base_mode_seal;

mod config;
pub use config::Config;

mod keypair;
pub use keypair::{gen_keypair, Keypair};

mod ciphertext;
pub use ciphertext::EncappedKeyAndCiphertext;

mod aead;
pub use aead::{Aead, AEAD_ALL};

mod kdf;
pub use kdf::{Kdf, KDF_ALL};

mod kem;
pub use kem::{Kem, KEM_ALL};

mod macros;
pub(crate) use macros::match_algo;

/**
A simple error type for failed id lookups
 */
#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct IdLookupError(&'static str);
impl std::fmt::Display for IdLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("id lookup error {}", self.0))
    }
}
impl std::error::Error for IdLookupError {}

pub(crate) fn from_bytes<T: Deserializable>(encoded: &[u8]) -> Result<T, HpkeError> {
    T::from_bytes(encoded)
}
