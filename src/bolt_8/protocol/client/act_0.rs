use crate::bolt_8::crypto::Sha256Digest;
use secp256k1::PublicKey;

/// Accumulates the state during the Act-0 of the handshake procedure.
pub struct Act0 {
    /// The static public key of the remote node.
    pub(super) rs_pk: PublicKey,

    /// The chaining key.
    pub(super) ck: [u8; 32],

    /// The handshake hash.
    pub(super) h: Sha256Digest,
}

impl Act0 {
    /// Initiates the Act-0 of the handshake procedure.
    pub fn new(rs_pk: PublicKey) -> Self {
        let mut h = Sha256Digest::new();

        h.update(b"Noise_XK_secp256k1_ChaChaPoly_SHA256"); // Protocol name;

        let ck = h.as_bytes().to_owned();

        h.update(b"lightning"); // Prologue;

        h.update(&rs_pk.serialize());

        Self { rs_pk, ck, h }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn it_accumulates_the_correct_state() {
        // Values used for testing are taken from BOLT-8 test vectors.
        // See: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors

        let rs_pk = hex!("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
        let rs_pk = PublicKey::from_slice(&rs_pk).unwrap();

        let act_0 = Act0::new(rs_pk);

        assert_eq! { act_0.rs_pk, rs_pk };
        assert_eq! { act_0.ck, hex!("2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1") };
        assert_eq! { act_0.h.as_bytes(), &hex!("8401b3fdcaaa710b5405400536a3d5fd7792fe8e7fe29cd8b687216fe323ecbd") };
    }
}
