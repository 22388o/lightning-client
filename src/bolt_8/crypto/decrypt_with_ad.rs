use crate::bolt_8::crypto::CryptoError;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305,
};
use color_eyre::eyre;
use digest::{generic_array::GenericArray, KeyInit};

/// Performs a ChaCha20-Poly1305 (IETF variant) decryption on the arguments passed.
///
/// Returns the decrypted message.
pub fn decrypt_with_ad(
    key: &[u8; 32],
    n: u64,
    ad: &[u8],
    cyphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    // This follows the Noise Protocol convention,
    // 32 zero bits, followed by a little-endian 64-bit value.
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());

    let payload = Payload {
        msg: cyphertext,
        aad: ad,
    };

    cipher
        .decrypt(GenericArray::from_slice(&nonce), payload)
        .map_err(|e| CryptoError::DecryptionFailed {
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

        let key = hex!("908b166535c01a935cf1e130a5fe895ab4e6f3ef8855d87e9b7581c4ab663ddc");
        let n = 0;
        let ad = hex!("38122f669819f906000621a14071802f93f2ef97df100097bcac3ae76c6dc0bf");
        let chipertext = hex!("6e2470b93aac583c9ef6eafca3f730ae");

        let x = decrypt_with_ad(&key, n, &ad, &chipertext).unwrap();

        assert!(x.is_empty());
    }
}
