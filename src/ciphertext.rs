#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        /**
        a simple struct to return the combined encapsulated key
        and ciphertext from seal
        */
        #[wasm_bindgen]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct EncappedKeyAndCiphertext {
            pub(crate) encapped_key: Vec<u8>,
            pub(crate) ciphertext: Vec<u8>
        }

        #[wasm_bindgen]
        impl EncappedKeyAndCiphertext {
            /// getter for encapped_key
            #[wasm_bindgen(getter)]
            pub fn encapped_key(&self) -> Vec<u8> {
                self.encapped_key.clone()
            }

            /// getter for ciphertext
            #[wasm_bindgen(getter)]
            pub fn ciphertext(&self) -> Vec<u8> {
                self.ciphertext.clone()
            }
        }

    } else {
        /**
        a simple open struct to return the combined encapsulated key
        and ciphertext from seal
        */
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct EncappedKeyAndCiphertext {
            /// the encapsulated encryption key
            pub encapped_key: Vec<u8>,
            /// the ciphertext, encrypted with the encapsulated key
            pub ciphertext: Vec<u8>
        }
    }
}

impl EncappedKeyAndCiphertext {
    /// returns (encapsulated key, ciphertext)
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.encapped_key, self.ciphertext)
    }
}
