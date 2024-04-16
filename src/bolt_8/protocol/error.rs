use crate::bolt_8::crypto::CryptoError;
use color_eyre::eyre;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("A cryptography operation has failed")]
    CryptographyFailure { source: eyre::Report },

    #[error("The '{0}' is not a known handshake version")]
    UnknownHandshakeVersion(u8),

    #[error("The '{hex}' is not a valid public key")]
    InvalidPublicKey { hex: String, source: eyre::Report },

    #[error("IO error")]
    IoError { source: eyre::Report },

    #[error("Invalid message length: {0}")]
    InvalidMessageLength(String),
}

impl From<CryptoError> for ProtocolError {
    fn from(e: CryptoError) -> Self {
        Self::CryptographyFailure {
            source: eyre::Report::new(e),
        }
    }
}

impl From<tokio::io::Error> for ProtocolError {
    fn from(e: tokio::io::Error) -> Self {
        Self::IoError {
            source: eyre::Report::new(e),
        }
    }
}
