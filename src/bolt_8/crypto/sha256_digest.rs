use sha2::{Digest, Sha256};

/// A wrapper for SHA256 that accumulates hashes.
pub struct Sha256Digest {
    digest: Option<[u8; 32]>,
}

impl Sha256Digest {
    /// Creates a new empty digest.
    pub fn new() -> Self {
        Self { digest: None }
    }

    /// Creates a new digest based on the previous hash and the data passed.
    pub fn update(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();

        if let Some(x) = std::mem::take(&mut self.digest) {
            hasher.update(x);
        }

        hasher.update(data);

        self.digest = Some(hasher.finalize().as_slice().try_into().unwrap());
    }

    /// Returns the current digest as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self.digest {
            Some(ref x) => x,
            None => &[0; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use secp256k1::PublicKey;

    #[test]
    fn it_accumulates_the_correct_digest() {
        // Values used for testing are taken from BOLT-8 test vectors.
        // See: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors

        let rs_pk = hex!("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
        let rs_pk = PublicKey::from_slice(&rs_pk).unwrap();

        let le_pk = hex!("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7");
        let le_pk = PublicKey::from_slice(&le_pk).unwrap();

        let mut h = Sha256Digest::new();

        h.update(b"Noise_XK_secp256k1_ChaChaPoly_SHA256");
        h.update(b"lightning");
        h.update(&rs_pk.serialize());
        h.update(&le_pk.serialize());

        assert_eq! { h.as_bytes(), &hex!("9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c") };
    }
}
