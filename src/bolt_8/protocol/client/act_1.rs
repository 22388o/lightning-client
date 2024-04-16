use crate::bolt_8::{
    crypto::{ecdh, encrypt_with_ad, hkdf, Sha256Digest},
    protocol::{client::Act0, ProtocolError},
};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Accumulates the state during the Act-1 of the handshake procedure.
pub struct Act1 {
    /// The static public key of the local node.
    pub(super) ls_pk: PublicKey,

    /// The static secret key of the local node.
    pub(super) ls_sk: SecretKey,

    /// The ephemeral public key of the local node.
    pub(super) le_pk: PublicKey,

    /// The ephemeral secret key of the local node.
    pub(super) le_sk: SecretKey,

    /// The chaining key.
    pub(super) ck: [u8; 32],

    /// The Poly1305 tag.
    pub(super) c: Vec<u8>,

    /// The handshake hash.
    pub(super) h: Sha256Digest,
}

impl Act1 {
    /// Initiates the Act-1 of the handshake procedure.
    pub fn new(act_0: Act0, ls_sk: SecretKey) -> Result<Self, ProtocolError> {
        let le_sk = SecretKey::new(&mut secp256k1::rand::thread_rng());

        Self::new_static(act_0, ls_sk, le_sk)
    }

    pub(super) fn new_static(
        act_0: Act0,
        ls_sk: SecretKey,
        le_sk: SecretKey,
    ) -> Result<Self, ProtocolError> {
        let Act0 { rs_pk, ck, mut h } = act_0;

        let ls_pk = PublicKey::from_secret_key(SECP256K1, &ls_sk);
        let le_pk = PublicKey::from_secret_key(SECP256K1, &le_sk);

        h.update(&le_pk.serialize());

        let es = ecdh(&rs_pk, &le_sk);

        let (ck, temp_k1) = hkdf(&ck, &es);

        let c = encrypt_with_ad(&temp_k1, 0, h.as_bytes(), b"")?;

        h.update(&c);

        Ok(Self {
            ls_pk,
            ls_sk,
            le_pk,
            le_sk,
            ck,
            c,
            h,
        })
    }

    /// Sends the message to the remote node.
    pub async fn send_message(
        &self,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ProtocolError> {
        stream.write_all(&self.message()).await?;

        Ok(())
    }

    // Returns the message to send to the remote node.
    //
    // The handshake message is exactly 50 bytes:
    //     - 1 byte for the handshake version;
    //     - 33 bytes for the compressed ephemeral public key of the initiator;
    //     - 16 bytes for the poly1305 tag;
    fn message(&self) -> [u8; 50] {
        let mut m = [0u8; 50];

        // Handshake version.
        //
        // A version of 0 indicates that no change is necessary,
        // while a non-zero version indicate that the client has deviated from the protocol.
        m[0] = 0;

        m[1..34].copy_from_slice(&self.le_pk.serialize()[..33]);
        m[34..].copy_from_slice(&self.c[..16]);

        m
    }
}

#[cfg(test)]
mod test {
    use super::*;
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

        let act_0 = Act0::new(rs_pk);

        let act_1 = Act1::new_static(act_0, ls_sk, le_sk).unwrap();

        assert_eq! { act_1.ls_pk.serialize(), hex!("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa") };
        assert_eq! { act_1.ls_sk, ls_sk };
        assert_eq! { act_1.le_pk.serialize(), hex!("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7") };
        assert_eq! { act_1.le_sk, le_sk };
        assert_eq! { act_1.ck, hex!("b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f") };
        assert_eq! { act_1.c, hex!("0df6086551151f58b8afe6c195782c6a") };
        assert_eq! { act_1.h.as_bytes(), &hex!("9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce") };

        assert_eq! { act_1.message(), hex!("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a") };
    }
}
