use color_eyre::eyre;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed { source: eyre::Report },

    #[error("Decryption failed")]
    DecryptionFailed { source: eyre::Report },
}
