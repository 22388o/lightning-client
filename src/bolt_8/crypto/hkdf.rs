use hkdf::Hkdf;
use sha2::Sha256;

/// [HMAC-based Extract-and-Expand Key Derivation Function (HKDF)][0].
///
/// Returns the chaining key (ck) and the intermediate key (temp_k).
///
/// [0]: https://datatracker.ietf.org/doc/html/rfc5869
pub fn hkdf(salt: &[u8], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    // According to the specification, the evaluation
    // should be performed with a zero-length info field.
    let info = &[];

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    // According to the specification, the expand should return
    // 64 bytes of cryptographic randomness.
    let mut buf = [0u8; 64];
    hk.expand(info, &mut buf).unwrap();

    let (ck, temp_k) = buf.split_at(32);

    (ck.try_into().unwrap(), temp_k.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn it_produces_the_correct_keys() {
        // Values used for testing are taken from BOLT-8 test vectors.
        // See: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors

        let salt = hex!("2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1");
        let ikm = hex!("1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3");

        let (ck, temp_k) = hkdf(&salt, &ikm);

        assert_eq! { ck, hex!("b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f") };
        assert_eq! { temp_k, hex!("e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f") };
    }
}
