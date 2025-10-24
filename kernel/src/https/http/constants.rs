//! Constants for HTTPS implementation
/// Kilobyte constant
const KB: usize = 1024;
/// Megabyte constant
const MB: usize = 1024 * KB;
/// Max buffer size for HTTP connections
pub const MAX_HTTP_BUFFER_SIZE: usize = MB;
/// Maximum number of headers in an HTTP request/response
pub const MAX_HTTP_HEADERS: usize = 16;
