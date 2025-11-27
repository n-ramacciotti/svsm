//! Constants for TLS management
/// The length of the TLS header in bytes.
pub const HEADER_LEN: usize = 5;
/// The position of the first length byte in the TLS record.
pub const FIRST_LEN_BYTE_POS: usize = 4;
/// The position of the second length byte in the TLS record.
pub const SECOND_LEN_BYTE_POS: usize = 3;
/// Additional fields for TLS records.
/// TLS ContentType field size in bytes
const CONTENT_TYPE: usize = 1;
/// AEAD overhead calculation: 16 bytes for GCM tag
const AEAD_OVERHEAD: usize = 16;
/// TLS overhead calculation: ContentType + Version + Length
const TLS_OVERHEAD: usize = CONTENT_TYPE + AEAD_OVERHEAD + HEADER_LEN;
/// Kilobyte constant
const KB: usize = 1024;
/// Maximum TLS record length in bytes
pub const MAX_TLS_RECORD_LEN: usize = 16 * KB;
/// Maximum TLS record length in bytes including overhead
const MAX_TLS_RECORD_LEN_WITH_OVERHEAD: usize = MAX_TLS_RECORD_LEN + TLS_OVERHEAD;
/// Input buffer size for TLS records
pub const IN_BUF_SIZE: usize = MAX_TLS_RECORD_LEN_WITH_OVERHEAD;
/// Output buffer size for TLS records
pub const OUT_BUF_SIZE: usize = MAX_TLS_RECORD_LEN_WITH_OVERHEAD;
