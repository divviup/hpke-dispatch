#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use num_enum::TryFromPrimitive;

/**
Aead represents an authenticated encryption with additional data
encryption function, as per [RFC9180§7.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3)
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
#[cfg_attr(feature = "cfg_eval", cfg_eval)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum Aead {
    #[cfg(feature = "aead-aes-gcm-128")]
    /// AES-128-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    AesGcm128 = 1,
    #[cfg(feature = "aead-aes-gcm-256")]
    /// AES-256-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    AesGcm256 = 2,
    #[cfg(feature = "aead-chacha-20-poly-1305")]
    /// ChaCha20Poly1305 [RFC8439](https://www.rfc-editor.org/info/rfc8439)
    ChaCha20Poly1305 = 3,
}

/// An iterable slice of [`Aead`] variants
pub const AEAD_ALL: &'static [Aead] = &[
    #[cfg(feature = "aead-aes-gcm-128")]
    Aead::AesGcm128,
    #[cfg(feature = "aead-aes-gcm-256")]
    Aead::AesGcm256,
    #[cfg(feature = "aead-chacha-20-poly-1305")]
    Aead::ChaCha20Poly1305,
];
