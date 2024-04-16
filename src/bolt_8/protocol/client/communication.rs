// TODO: Remove when sending messages is implemented.
#![allow(dead_code)]

use crate::bolt_8::{
    crypto::decrypt_with_ad,
    protocol::{client::Act3, ProtocolError},
};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Defines the communication phase of the protocol.
///
/// Contains the required state to perform encrypted communication with a remote node.
pub struct Communication {
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

impl Communication {
    /// Initiates the communication phase.
    pub fn new(act_3: Act3) -> Self {
        let Act3 {
            c: _,
            t: _,
            sk,
            rk,
            sn,
            rn,
            sck,
            rck,
        } = act_3;

        Self {
            sk,
            rk,
            sn,
            rn,
            sck,
            rck,
        }
    }

    /// Reads a message from the remote node.
    pub async fn read_message(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut lc = [0u8; 18];
        stream.read_exact(&mut lc).await?;

        let l = decrypt_with_ad(&self.rk, self.rn, &[], &lc)?;
        self.rn += 1;

        if l.len() != 2 {
            return Err(ProtocolError::InvalidMessageLength(format!(
                "want 2 bytes, got {}",
                l.len(),
            )));
        }

        let l = u16::from_be_bytes([l[0], l[1]]);

        let mut c = vec![0; l as usize + 16];
        stream.read_exact(&mut c).await?;

        let p = decrypt_with_ad(&self.rk, self.rn, &[], &c)?;
        self.rn += 1;

        Ok(p)
    }
}
