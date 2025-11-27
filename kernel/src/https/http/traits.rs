extern crate alloc;
use super::error::HttpError;
use alloc::vec::Vec;

/// Trait to convert HTTP messages to bytes for transmission
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Generic parser trait and implementations to avoid duplication between
/// request and response parsing. Each parser implements `init_builder_from_headers` which
/// attempts to parse the provided buffer and either returns None when
/// parsing is partial, or Some((body_start, content_length, builder)) on
/// success.
pub trait MessageReceivable: Sized {
    type Builder;

    /// Initialize a builder from the parsed headers in the provided buffer.
    fn init_builder_from_headers(
        buf: &[u8],
    ) -> Result<Option<(usize, usize, Self::Builder)>, HttpError>;
    /// Construct the message from the partial builder and body.
    fn get_message_from_parts(builder: Self::Builder, body: Vec<u8>) -> Result<Self, HttpError>;
}
