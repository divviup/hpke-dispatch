#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{from_bytes, match_algo, Config, EncappedKeyAndCiphertext, HpkeError};
use hpke::Serializable;

/**
`base_mode_seal` provides an interface to [`hpke::single_shot_seal`]
that does not require compile time selection of an
algorithm. Instead, the selected algorithm is provided through the
[`Config`] passed as the first argument.

Requires the `base-mode-seal` crate feature to be enabled.

# Errors

This will return an `Result::Err` variant if:

* we are unable to deserialize the recipient public key
* there is an error in key encapsultion
* there is an error in encryption

 */

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg(feature = "base-mode-seal")]
pub fn base_mode_seal(
    config: &Config,
    pk_recip: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncappedKeyAndCiphertext, HpkeError> {
    let Config { aead, kdf, kem } = *config;

    fn seal<AeadT, KdfT, KemT>(
        pk_recip: &[u8],
        info: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EncappedKeyAndCiphertext, HpkeError>
    where
        AeadT: hpke::aead::Aead,
        KdfT: hpke::kdf::Kdf,
        KemT: hpke::kem::Kem,
    {
        let (encapped_key, ciphertext) = hpke::single_shot_seal::<AeadT, KdfT, KemT, _>(
            &hpke::OpModeS::Base,
            &from_bytes(pk_recip)?,
            info,
            plaintext,
            aad,
            &mut rand::thread_rng(),
        )?;

        Ok(EncappedKeyAndCiphertext {
            encapped_key: encapped_key.to_bytes().to_vec(),
            ciphertext,
        })
    }

    let seal = match_algo!(aead, kdf, kem, seal);
    seal(pk_recip, info, plaintext, aad)
}
