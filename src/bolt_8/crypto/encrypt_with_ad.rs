use crate::bolt_8::crypto::CryptoError;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305,
};
use color_eyre::eyre;
use digest::{generic_array::GenericArray, KeyInit};

/// Performs a ChaCha20-Poly1305 (IETF variant) encryption on the arguments passed.
///
/// Returns the encrypted message.
pub fn encrypt_with_ad(
    key: &[u8; 32],
    n: u64,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    // This follows the Noise Protocol convention,
    // 32 zero bits, followed by a little-endian 64-bit value.
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());

    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };

    cipher
        .encrypt(GenericArray::from_slice(&nonce), payload)
        .map_err(|e| CryptoError::EncryptionFailed {
            source: eyre::eyre!(e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn it_produces_the_correct_message() {
        // Values used for testing are taken from BOLT-8 test vectors.
        // See: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors

        let key = hex!("e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f");
        let n = 0;
        let ad = hex!("9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c");
        let plaintext = b"";

        let c = encrypt_with_ad(&key, n, &ad, plaintext).unwrap();

        assert_eq! { c, hex!("0df6086551151f58b8afe6c195782c6a") };
    }
}
