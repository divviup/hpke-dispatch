#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::Keypair;
use num_enum::TryFromPrimitive;

/**
Kem represents an asymmetric key encapsulation mechanism, as per
[RFC9180§7.1][section-7.1]. Currently only two of options listed in
the hpke draft are available.

[section-7.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
*/
#[non_exhaustive]
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
#[cfg_attr(feature = "cfg_eval", cfg_eval)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum Kem {
    /// DHKEM(P-256, HKDF-SHA256) [NISTCurves](https://doi.org/10.6028/nist.fips.186-4)
    #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
    DhP256HkdfSha256 = 16,

    /// DHKEM(X25519, HKDF-SHA256) [RFC7748](https://www.rfc-editor.org/info/rfc7748)
    #[cfg(feature = "kem-x25519-hkdf-sha256")]
    X25519HkdfSha256 = 32,
}

impl Kem {
    /// generate a [`Keypair`] for this [`Config`] or [`Kem`].
    #[must_use]
    pub fn gen_keypair(self) -> Keypair {
        crate::gen_keypair(self)
    }
}

/// An iterable slice of [`Kem`] variants
pub const KEM_ALL: &[Kem] = &[
    #[cfg(feature = "kem-dh-p256-hkdf-sha256")]
    Kem::DhP256HkdfSha256,
    #[cfg(feature = "kem-x25519-hkdf-sha256")]
    Kem::X25519HkdfSha256,
];
