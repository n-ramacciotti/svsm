use httparse::Error as HttpParseError;

/// Enumeration of HTTP-related errors.
#[derive(Clone, Copy, Debug)]
pub enum HttpError {
    GenericError,
    ConnectionClosed,
    RequestAlreadySent,
    ResponseAlreadySent,
    RequestAlreadyReceived,
    ResponseAlreadyReceived,
    BufferSizeError(usize, usize),
    HttpParseError(HttpParseError),
}

impl From<HttpParseError> for HttpError {
    fn from(err: HttpParseError) -> Self {
        HttpError::HttpParseError(err)
    }
}
