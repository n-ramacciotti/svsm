// Constants for TLS management
pub const HEADER_LEN: usize = 5;
pub const FIRST_LEN_BYTE_POS: usize = 4;
pub const SECOND_LEN_BYTE_POS: usize = 3;
const CONTENT_TYPE: usize = 1; // TLS ContentType field size in bytes
const AEAD_OVERHEAD: usize = 16 + CONTENT_TYPE; // Bytes added by AEAD encryption
pub const IN_BUF_SIZE: usize = 16 * 1024 + AEAD_OVERHEAD + HEADER_LEN;
pub const OUT_BUF_SIZE: usize = 1024;
