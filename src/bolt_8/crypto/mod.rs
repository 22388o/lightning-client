//! This module contains all the cryptographic and hashing
//! functionality required by the BOLT-8 protocol.

mod decrypt_with_ad;
mod ecdh;
mod encrypt_with_ad;
mod error;
mod hkdf;
mod sha256_digest;

pub use self::decrypt_with_ad::decrypt_with_ad;
pub use self::ecdh::ecdh;
pub use self::encrypt_with_ad::encrypt_with_ad;
pub use self::error::CryptoError;
pub use self::hkdf::hkdf;
pub use self::sha256_digest::Sha256Digest;
