//! This module defines the BOLT-8 protocol.

mod client;
mod error;

pub use self::client::ClientProtocol;
pub use self::error::ProtocolError;
