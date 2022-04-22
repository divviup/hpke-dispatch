#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{from_bytes, match_algo, Config, HpkeError};

/**
`base_mode_open` provides an interface to [`hpke::single_shot_open`]
that does not require compile time selection of an algorithm. Instead,
the selected algorithm is provided through the [`Config`] passed as
the first argument.

Requires the `base-mode-open` crate feature to be enabled.

# Errors

This will return an `Result::Err` variant if:

* we are unable to deserialize the private key or encapsulated key
* there is an error in key decapsulation
* there is an error in decryption
 */

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
#[cfg(feature = "base-mode-open")]
pub fn base_mode_open(
    config: &Config,
    private_key: &[u8],
    encapped_key: &[u8],
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    let Config { aead, kdf, kem } = *config;
    let open = match_algo!(aead, kdf, kem, open);
    open(private_key, encapped_key, info, ciphertext, aad)
}

fn open<AeadT, KdfT, KemT>(
    private_key: &[u8],
    encapped_key: &[u8],
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError>
where
    AeadT: hpke::aead::Aead,
    KdfT: hpke::kdf::Kdf,
    KemT: hpke::kem::Kem,
{
    hpke::single_shot_open::<AeadT, KdfT, KemT>(
        &hpke::OpModeR::Base,
        &from_bytes(private_key)?,
        &from_bytes(encapped_key)?,
        info,
        ciphertext,
        aad,
    )
    .map_err(Into::into) // this is noop unless compiling for wasm.
}
