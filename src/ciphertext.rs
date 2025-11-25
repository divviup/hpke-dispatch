/**
a simple struct to return the combined encapsulated key
and ciphertext from seal
*/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncappedKeyAndCiphertext {
    /// the encapsulated encryption key
    pub encapped_key: Vec<u8>,

    /// the ciphertext, encrypted with the key
    pub ciphertext: Vec<u8>,
}

impl EncappedKeyAndCiphertext {
    /// returns (encapsulated key, ciphertext)
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.encapped_key, self.ciphertext)
    }
}
