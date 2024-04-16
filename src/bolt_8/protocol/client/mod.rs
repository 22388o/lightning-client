mod act_0;
mod act_1;
mod act_2;
mod act_3;
mod communication;

use self::{act_0::Act0, act_1::Act1, act_2::Act2, act_3::Act3, communication::Communication};
use crate::bolt_8::protocol::ProtocolError;
use secp256k1::{PublicKey, SecretKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// Defines a step-by-step procedure for performing a handshake
/// and initiating encrypted communication with a remote node.
pub struct ClientProtocol<T> {
    state: T,
}

impl ClientProtocol<()> {
    /// Creates a new session with a remote node.
    pub fn new(rs_pk: PublicKey) -> ClientProtocol<Act0> {
        ClientProtocol {
            state: Act0::new(rs_pk),
        }
    }
}

impl ClientProtocol<Act0> {
    /// Proceeds to the next handshake phase.
    pub fn next(self, ls_sk: SecretKey) -> Result<ClientProtocol<Act1>, ProtocolError> {
        Ok(ClientProtocol {
            state: Act1::new(self.state, ls_sk)?,
        })
    }
}

impl ClientProtocol<Act1> {
    /// Sends the message to the remote node.
    pub async fn send_message(
        &self,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ProtocolError> {
        self.state.send_message(stream).await
    }

    /// Proceeds to the next handshake phase.
    pub async fn next(
        self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<ClientProtocol<Act2>, ProtocolError> {
        let mut buf = [0u8; 50];
        stream.read_exact(&mut buf).await?;

        Ok(ClientProtocol {
            state: Act2::new(self.state, &buf)?,
        })
    }
}

impl ClientProtocol<Act2> {
    /// Proceeds to the next handshake phase.
    pub fn next(self) -> Result<ClientProtocol<Act3>, ProtocolError> {
        Ok(ClientProtocol {
            state: Act3::new(self.state)?,
        })
    }
}

impl ClientProtocol<Act3> {
    /// Sends the message to the remote node.
    pub async fn send_message(
        &self,
        stream: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), ProtocolError> {
        self.state.send_message(stream).await
    }

    /// Proceeds to the communication phase.
    pub fn next(self) -> ClientProtocol<Communication> {
        ClientProtocol {
            state: Communication::new(self.state),
        }
    }
}

impl ClientProtocol<Communication> {
    /// Reads a message from the remote node.
    pub async fn read_message(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<Vec<u8>, ProtocolError> {
        self.state.read_message(stream).await
    }
}
