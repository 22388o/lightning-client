use crate::bolt_8::{
    crypto::{ecdh, encrypt_with_ad, hkdf},
    protocol::{client::Act2, ProtocolError},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Accumulates the state during the Act-3 of the handshake procedure.
pub struct Act3 {
    /// The static public key encrypted with the ChaCha20 stream cipher.
    pub(super) c: Vec<u8>,

    /// The final authenticating tag.
    pub(super) t: Vec<u8>,

    /// The sending encryption key.
    pub(super) sk: [u8; 32],

    /// The receiving decryption key.
    pub(super) rk: [u8; 32],

    /// The sending nonce.
    pub(super) sn: u64,

    /// The receiving nonce.
    pub(super) rn: u64,

    /// The sending chaining key.
    pub(super) sck: [u8; 32],

    /// The receiving chaining key.
    pub(super) rck: [u8; 32],
}

impl Act3 {
    /// Initiates the Act-3 of the handshake procedure.
    pub fn new(act_2: Act2) -> Result<Self, ProtocolError> {
        let Act2 {
            ls_pk,
            ls_sk,
            re_pk,
            ck,
            temp_k2,
            mut h,
        } = act_2;

        let c = encrypt_with_ad(&temp_k2, 1, h.as_bytes(), &ls_pk.serialize())?;

        h.update(&c);

        let se = ecdh(&re_pk, &ls_sk);

        let (ck, temp_k3) = hkdf(&ck, &se);

        let t = encrypt_with_ad(&temp_k3, 0, h.as_bytes(), b"")?;

        let (sk, rk) = hkdf(&ck, b"");

        Ok(Self {
            c,
            t,
            sk,
            rk,
            sn: 0,
            rn: 0,
            sck: ck,
            rck: ck,
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
    // The handshake is exactly 66 bytes:
    //     - 1 byte for the handshake version;
    //     - 33 bytes for the static public key encrypted with the ChaCha20 stream cipher;
    //     - 16 bytes for the encrypted public key's tag generated via the AEAD construction;
    //     - 16 bytes for a final authenticating tag;
    fn message(&self) -> [u8; 66] {
        let mut m = [0u8; 66];

        // Handshake version.
        //
        // A version of 0 indicates that no change is necessary,
        // while a non-zero version indicate that the client has deviated from the protocol.
        m[0] = 0;

        m[1..50].copy_from_slice(&self.c[..49]);
        m[50..].copy_from_slice(&self.t[..16]);

        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt_8::protocol::client::{Act0, Act1};
    use hex_literal::hex;
    use secp256k1::{PublicKey, SecretKey};

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

        let rm = hex!("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");

        let act_2 = Act2::new(act_1, &rm).unwrap();

        let act_3 = Act3::new(act_2).unwrap();

        assert_eq! { act_3.c, hex!("b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c3822") };
        assert_eq! { act_3.t, hex!("8dc68b1c466263b47fdf31e560e139ba") };
        assert_eq! { act_3.sk, hex!("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9") };
        assert_eq! { act_3.rk, hex!("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442") };
        assert_eq! { act_3.sn, 0 };
        assert_eq! { act_3.rn, 0 };
        assert_eq! { act_3.sck, hex!("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01") };
        assert_eq! { act_3.rck, hex!("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01") };
        assert_eq! { act_3.message(), hex!("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba") };
    }
}
