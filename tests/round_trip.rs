use hpke_dispatch::*;

const AAD: &[u8] = b"associated data";
const PLAINTEXT: &[u8] = b"plaintext test message";
const APP_INFO: &[u8] = b"application info";

fn test_round_trip(config: Config) {
    let (private_key, public_key) = config.kem.gen_keypair().into_parts();

    let (encapped_key, ciphertext) = config
        .base_mode_seal(&public_key, APP_INFO, PLAINTEXT, AAD)
        .unwrap_or_else(|e| panic!("problem with {config:?} base_mode_seal ({e:?})"))
        .into_parts();

    let plaintext = config
        .base_mode_open(&private_key, &encapped_key, &ciphertext, APP_INFO, AAD)
        .unwrap_or_else(|e| panic!("problem with {config:?} base_mode_open ({e:?})"));

    assert_eq!(
        plaintext, PLAINTEXT,
        "round trip plaintext did not match for {config:?}"
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn test_all_round_trips() {
    for ((aead, kdf), kem) in AEAD_ALL.iter().zip(KDF_ALL).zip(KEM_ALL) {
        test_round_trip(Config {
            aead: *aead,
            kdf: *kdf,
            kem: *kem,
        });
    }
}
