use crate::IdLookupError;
use num_enum::TryFromPrimitive;
use std::str::FromStr;

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
pub enum Aead {
    #[cfg(feature = "aead-aes")]
    /// AES-128-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    AesGcm128 = 1,
    #[cfg(feature = "aead-aes")]
    /// AES-256-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    AesGcm256 = 2,
    #[cfg(feature = "aead-chacha")]
    /// ChaCha20Poly1305 [RFC8439](https://www.rfc-editor.org/info/rfc8439)
    ChaCha20Poly1305 = 3,
}

impl FromStr for Aead {
    type Err = IdLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s.to_lowercase().replace('-', "") {
            #[cfg(feature = "aead-aes")]
            "aesgcm128" | "aes128gcm" => Ok(Self::AesGcm128),
            #[cfg(feature = "aead-aes")]
            "aesgcm256" | "aes256gcm" => Ok(Self::AesGcm256),
            #[cfg(feature = "aead-chacha")]
            "chacha20poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(IdLookupError("aead not recognized")),
        }
    }
}

/// An iterable slice of [`Aead`] variants
pub const AEAD_ALL: &[Aead] = &[
    #[cfg(feature = "aead-aes")]
    Aead::AesGcm128,
    #[cfg(feature = "aead-aes")]
    Aead::AesGcm256,
    #[cfg(feature = "aead-chacha")]
    Aead::ChaCha20Poly1305,
];
