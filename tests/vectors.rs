use hpke_dispatch::Config;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct EncryptionRecord {
    #[serde(with = "hex")]
    aad: Vec<u8>,
    #[serde(with = "hex", rename = "ct")]
    ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
    #[serde(with = "hex", rename = "pt")]
    plaintext: Vec<u8>,
}

/// This structure corresponds to the format of the JSON test vectors included with the HPKE
/// RFC. Only a subset of fields are used; all intermediate calculations are ignored.
#[derive(Deserialize, Debug)]
struct TestVector {
    mode: u16,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    #[serde(with = "hex")]
    info: Vec<u8>,
    #[serde(with = "hex", rename = "enc")]
    encapped_key: Vec<u8>,
    #[serde(with = "hex", rename = "skRm")]
    serialized_private_key: Vec<u8>,
    #[serde(with = "hex")]
    base_nonce: Vec<u8>,
    encryptions: Vec<EncryptionRecord>,
}

#[test]
fn decrypt_test_vectors() {
    let test_vectors: Vec<TestVector> =
        serde_json::from_str(include_str!("./test-vectors.json")).unwrap(); // https://github.com/cfrg/draft-irtf-cfrg-hpke/raw/master/test-vectors.json

    let test_vectors = test_vectors
        .into_iter()
        .filter(|v| v.mode == 0)
        .filter_map(|test_vector| {
            let config =
                Config::try_from_ids(test_vector.aead_id, test_vector.kdf_id, test_vector.kem_id)
                    .ok()?;

            Some((config, test_vector))
        })
        .collect::<Vec<_>>();

    for (config, test_vector) in test_vectors {
        for encryption in &test_vector.encryptions {
            if encryption.nonce != test_vector.base_nonce {
                continue;
            }

            let plaintext = config
                .base_mode_open(
                    &test_vector.serialized_private_key,
                    &test_vector.encapped_key,
                    &test_vector.info,
                    &encryption.ciphertext,
                    &encryption.aad,
                )
                .unwrap_or_else(|e| {
                    panic!("{e:?}\n\n{config:?}\n\n{encryption:#?}\n\n{test_vector:#?}")
                });

            assert_eq!(plaintext, encryption.plaintext);
        }
    }
}
