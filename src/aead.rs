use std::str::FromStr;

use num_enum::TryFromPrimitive;

use crate::IdLookupError;

/// An authenticated encryption with additional data encryption function, as per [RFC9180§7.3][1].
///
/// [1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub enum Aead {
    /// AES-128-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    #[cfg(feature = "aes")]
    AesGcm128 = 1,
    /// AES-256-GCM [GCM](https://doi.org/10.6028/nist.sp.800-38d)
    #[cfg(feature = "aes")]
    AesGcm256 = 2,
    /// ChaCha20Poly1305 [RFC8439](https://www.rfc-editor.org/info/rfc8439)
    #[cfg(feature = "chacha")]
    ChaCha20Poly1305 = 3,
}

impl FromStr for Aead {
    type Err = IdLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s.to_lowercase().replace('-', "") {
            #[cfg(feature = "aes")]
            "aesgcm128" | "aes128gcm" => Ok(Self::AesGcm128),
            #[cfg(feature = "aes")]
            "aesgcm256" | "aes256gcm" => Ok(Self::AesGcm256),
            #[cfg(feature = "chacha")]
            "chacha20poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(IdLookupError("aead not recognized")),
        }
    }
}

/// An iterable slice of [`Aead`] variants
pub const AEAD_ALL: &[Aead] = &[
    #[cfg(feature = "aes")]
    Aead::AesGcm128,
    #[cfg(feature = "aes")]
    Aead::AesGcm256,
    #[cfg(feature = "chacha")]
    Aead::ChaCha20Poly1305,
];
