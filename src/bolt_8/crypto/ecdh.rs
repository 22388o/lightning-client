use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

/// Performs an Elliptic-Curve Diffie-Hellman operation.
///
/// Returns the SHA256 digest of the generated point.
pub fn ecdh(pk: &PublicKey, sk: &SecretKey) -> [u8; 32] {
    SharedSecret::new(pk, sk).secret_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn it_produces_the_correct_digest() {
        // Values used for testing are taken from BOLT-8 test vectors.
        // See: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors

        let pk = hex!("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
        let pk = PublicKey::from_slice(&pk).unwrap();

        let sk = hex!("1212121212121212121212121212121212121212121212121212121212121212");
        let sk = SecretKey::from_slice(&sk).unwrap();

        let es = ecdh(&pk, &sk);

        assert_eq! { es, hex!("1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3") };
    }
}
