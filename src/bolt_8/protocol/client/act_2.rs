use crate::bolt_8::{
    crypto::{decrypt_with_ad, ecdh, hkdf, Sha256Digest},
    protocol::{client::Act1, ProtocolError},
};
use color_eyre::eyre;
use secp256k1::{PublicKey, SecretKey};

/// Accumulates the state during the Act-2 of the handshake procedure.
pub struct Act2 {
    /// The static public key of the local node.
    pub(super) ls_pk: PublicKey,

    /// The static secret key of the local node.
    pub(super) ls_sk: SecretKey,

    /// The ephemeral public key of the remote node.
    pub(super) re_pk: PublicKey,

    /// The chaining key.
    pub(super) ck: [u8; 32],

    /// The intermediate key.
    pub(super) temp_k2: [u8; 32],

    /// The handshake hash.
    pub(super) h: Sha256Digest,
}

impl Act2 {
    /// Initiates the Act-2 of the handshake procedure.
    pub fn new(act_1: Act1, rm: &[u8; 50]) -> Result<Self, ProtocolError> {
        let Act1 {
            ls_pk,
            ls_sk,
            le_pk: _,
            le_sk,
            ck,
            c: _,
            mut h,
        } = act_1;

        let (v, re_pk, c) = (rm[0], &rm[1..34], &rm[34..]);

        if v != 0 {
            return Err(ProtocolError::UnknownHandshakeVersion(v));
        }

        let re_pk = PublicKey::from_slice(re_pk).map_err(|e| ProtocolError::InvalidPublicKey {
            hex: hex::encode(re_pk),
            source: eyre::Report::new(e),
        })?;

        h.update(&re_pk.serialize());

        let ee = ecdh(&re_pk, &le_sk);

        let (ck, temp_k2) = hkdf(&ck, &ee);

        let _ = decrypt_with_ad(&temp_k2, 0, h.as_bytes(), c)?;

        h.update(c);

        Ok(Self {
            ls_pk,
            ls_sk,
            re_pk,
            ck,
            temp_k2,
            h,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt_8::protocol::client::Act0;
    use hex_literal::hex;

    #[test]
    fn it_accumulates_the_correct_state() {
        // Values used for testing are taken from BOLT-8 test vectors.
        // See: https://github.com/lightning/bolts/blob/master/08-transport.md#appendix-a-transport-test-vectors

        let rs_pk = hex!("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
        let rs_pk = PublicKey::from_slice(&rs_pk).unwrap();

        let ls_sk = hex!("1111111111111111111111111111111111111111111111111111111111111111");
        let ls_sk = SecretKey::from_slice(&ls_sk).unwrap();

        let le_sk = hex!("1212121212121212121212121212121212121212121212121212121212121212");
        let le_sk = SecretKey::from_slice(&le_sk).unwrap();

        let re_pk = hex!("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");
        let re_pk = PublicKey::from_slice(&re_pk).unwrap();

        let act_0 = Act0::new(rs_pk);

        let act_1 = Act1::new_static(act_0, ls_sk, le_sk).unwrap();

        let rm = hex!("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");

        let act_2 = Act2::new(act_1, &rm).unwrap();

        assert_eq! { act_2.re_pk, re_pk };
        assert_eq! { act_2.ck, hex!("e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba") };
        assert_eq! { act_2.temp_k2, hex!("908b166535c01a935cf1e130a5fe895ab4e6f3ef8855d87e9b7581c4ab663ddc") };
        assert_eq! { act_2.h.as_bytes(), &hex!("90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72") };
    }
}
