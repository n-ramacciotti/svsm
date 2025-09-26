// Private modules for TLS implementation
mod buffer;
mod constant;
mod crypto_provider;
mod key_logger;
mod time_provider;

// Public modules for TLS implementation
pub mod connection;
pub mod error;
pub mod examples;
pub mod http;
pub mod https_peer;
pub mod random;
