#![cfg_attr(feature = "cfg_eval", feature(cfg_eval))]
#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    missing_copy_implementations,
    rustdoc::missing_crate_level_docs,
    missing_debug_implementations,
    nonstandard_style,
    unused_qualifications
)]
#![warn(missing_docs, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::missing_errors_doc
)]
#![doc = include_str!("../README.md")]

use hpke::Deserializable;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

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

/**
A simple error type for failed id lookups
 */
#[derive(Copy, Clone, Debug)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
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
    T::from_bytes(encoded).map_err(Into::into)
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        /**
        a newtype wrapper for HpkeError so we can use it in wasm_bindgen
         */
        #[wasm_bindgen]
        #[derive(Debug, Clone, Copy)]
        pub struct HpkeError(hpke::HpkeError);
        impl From<hpke::HpkeError> for HpkeError {
            fn from(h: hpke::HpkeError) -> Self {
                Self(h)
            }
        }

        #[cfg_attr(feature = "wee-alloc", global_allocator)]
        #[cfg(feature = "wee-alloc")]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    } else {
        pub use hpke::HpkeError;
    }
}
