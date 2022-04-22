#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{
    base_mode_open, base_mode_seal, Aead, EncappedKeyAndCiphertext, HpkeError, IdLookupError, Kdf,
    Kem,
};
/**
Config is an open struct that contains an ([`Aead`], [`Kdf`], [`Kem`])
algorithmic triple. This can be used with [`Config::base_mode_seal`],
[`Config::base_mode_open`], [`base_mode_seal`], or [`base_mode_open`].
*/
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg_attr(
    feature = "serde",
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[cfg_attr(feature = "serde", serde(crate = "serde_crate"))]
pub struct Config {
    /// the [authenticated encryption with additional data encryption function](crate::Aead) to be used
    pub aead: Aead,
    /// the [key derivation function](crate::Kdf) to be used
    pub kdf: Kdf,
    /// the [asymmetric key encapsulation mechanism](crate::Kem) to be used
    pub kem: Kem,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl Config {
    /**
    base_mode_seal provides an interface to [`hpke::single_shot_seal`] that does
    not require compile time selection of an algorithm. Instead, the
    selected algorithm is provided through the [`Config`] that this
    method is called on.

    Requires the `base-mode-seal` crate feature to be enabled.

    # Errors

    This will return an `Result::Err` variant if:

     * we are unable to deserialize the recipient public key
     * there is an error in key encapsultion
     * there is an error in encryption

     */
    #[cfg(feature = "base-mode-seal")]
    pub fn base_mode_seal(
        &self,
        recipient_public_key: &[u8],
        info: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncappedKeyAndCiphertext, HpkeError> {
        base_mode_seal(self, recipient_public_key, info, plaintext, aad)
    }

    /**
    base_mode_open provides an interface to [`hpke::single_shot_open`]
    that does not require compile time selection of an
    algorithm. Instead, the selected algorithm is provided through the
    [`Config`] that this method is called on.

    Requires the `base-mode-open` crate feature to be enabled.

    # Errors

    This will return an `Result::Err` variant if:

    * we are unable to deserialize the private key or encapsulated key
    * there is an error in key decapsulation
    * there is an error in decryption

    */
    #[cfg(feature = "base-mode-open")]
    pub fn base_mode_open(
        &self,
        private_key: &[u8],
        encapped_key: &[u8],
        info: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        base_mode_open(self, private_key, encapped_key, info, ciphertext, aad)
    }

    /// Attempt to convert three u16 ids into a valid config. The id mappings are defined in the draft.
    #[allow(clippy::use_self)] // wasm_bindgen gets confused about Self
    pub fn try_from_ids(aead_id: u16, kdf_id: u16, kem_id: u16) -> Result<Config, IdLookupError> {
        Ok(Self {
            aead: aead_id.try_into().map_err(|_| IdLookupError("aead"))?,
            kdf: kdf_id.try_into().map_err(|_| IdLookupError("kdf"))?,
            kem: kem_id.try_into().map_err(|_| IdLookupError("kem"))?,
        })
    }
}
