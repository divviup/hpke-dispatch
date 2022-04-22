#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use num_enum::TryFromPrimitive;

/**
Kdf represents an key derivation function, as per
[RFC9180§7.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2)
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
pub enum Kdf {
    #[cfg(feature = "kdf-sha256")]
    /// Sha256 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    Sha256 = 1,
    #[cfg(feature = "kdf-sha384")]
    /// Sha384 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    Sha384 = 2,
    #[cfg(feature = "kdf-sha512")]
    /// Sha512 [RFC5869](https://www.rfc-editor.org/info/rfc5869)
    Sha512 = 3,
}

/// An iterable slice of [`Kdf`] variants
pub const KDF_ALL: &[Kdf] = &[
    #[cfg(feature = "kdf-sha256")]
    Kdf::Sha256,
    #[cfg(feature = "kdf-sha384")]
    Kdf::Sha384,
    #[cfg(feature = "kdf-sha512")]
    Kdf::Sha512,
];
