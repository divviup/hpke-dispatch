use crate::{from_bytes, Config, EncappedKeyAndCiphertext};
use hpke::{HpkeError, Serializable};

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
#[cfg(feature = "base-mode-seal")]
pub fn base_mode_seal(
    config: &Config,
    recipient_public_key: &[u8],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncappedKeyAndCiphertext, HpkeError> {
    let Config { aead, kdf, kem } = *config;
    let seal = match_algo!(aead, kdf, kem, seal);
    seal(recipient_public_key, info, plaintext, aad)
}

fn seal<AeadT, KdfT, KemT>(
    recipient_public_key: &[u8],
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
        &from_bytes(recipient_public_key)?,
        info,
        plaintext,
        aad,
        &mut rand::rng(),
    )?;

    Ok(EncappedKeyAndCiphertext {
        encapped_key: encapped_key.to_bytes().to_vec(),
        ciphertext,
    })
}
