// Buffer management for TLS records
extern crate alloc;

use super::constants::{FIRST_LEN_BYTE_POS, HEADER_LEN, MAX_TLS_RECORD_LEN, SECOND_LEN_BYTE_POS};
use super::error::TlsError;
use alloc::vec;
use alloc::vec::Vec;

/// A buffer structure to manage TLS records, allowing for efficient reading and writing
/// of data while handling partial reads/writes and discarding processed data.
#[derive(Debug)]
pub struct TlsBuffer {
    // The underlying byte buffer
    buf: Vec<u8>,
    // The first used (valid, non-discarded) byte in the buffer
    head: usize,
    // The first unused byte in the buffer
    tail: usize,
}

// fixme: input buffer is different from output buffer
// maybe we should have two different structs

impl TlsBuffer {
    /// Create a new [`TlsBuffer`] with the specified size
    pub fn new(size: usize) -> Self {
        Self {
            buf: vec![0u8; size],
            head: 0,
            tail: 0,
        }
    }

    /// Get a mutable reference to the currently used portion of the buffer
    pub fn curr_used_buf_as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.head..self.tail]
    }

    /// Get a reference to the currently used portion of the buffer
    pub fn curr_used_buf_as_ref(&self) -> &[u8] {
        &self.buf[self.head..self.tail]
    }

    /// Get a mutable reference to the remaining (unused) portion of the buffer
    pub fn remaining_buf_as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.tail..]
    }

    /// Get a reference to the remaining (unused) portion of the buffer of the specified size
    pub fn mutable_slice_from_remaining(&mut self, size: usize) -> Result<&mut [u8], TlsError> {
        if self.tail + size > self.buf.len() {
            return Err(TlsError::BufferTooSmall);
        }
        Ok(&mut self.buf[self.tail..self.tail + size])
    }

    /// From the current position (tail), extract the length of the TLS record
    /// by reading the appropriate bytes in the TLS header.
    /// Perform basic sanity checks on the TLS record structure
    pub fn extract_record_len_from_current_position(&self) -> Result<usize, TlsError> {
        if self.tail + HEADER_LEN > self.buf.len() {
            return Err(TlsError::BufferTooSmall);
        }

        let content_type = self.buf[self.tail];
        let version = (self.buf[self.tail + 1] as u16) << 8 | (self.buf[self.tail + 2] as u16);
        let record_len = ((self.buf[self.tail + SECOND_LEN_BYTE_POS] as usize) << 8)
            | (self.buf[self.tail + FIRST_LEN_BYTE_POS] as usize);

        if !(0x14..=0x17).contains(&content_type) {
            log::info!("Invalid TLS record content type: {:?}", content_type);
            return Err(TlsError::InvalidContentType);
        }

        if !(0x0301..=0x0304).contains(&version) {
            log::info!("Invalid TLS record version: {:?}", version);
            return Err(TlsError::InvalidRecordVersion);
        }

        if record_len == 0 || record_len > MAX_TLS_RECORD_LEN {
            return Err(TlsError::InvalidRecordLength);
        }

        Ok(record_len)
    }

    /// Advance the tail pointer by `n` bytes, marking them as used
    pub fn advance_used(&mut self, n: usize) -> Result<(), TlsError> {
        if self.tail + n > self.buf.len() {
            return Err(TlsError::BufferTooSmall);
        }
        self.tail += n;
        Ok(())
    }

    /// Reset the buffer to an empty state, discarding all used data
    pub fn reset_used(&mut self) {
        self.head = 0;
        self.tail = 0;
    }

    /// Ensure that there is enough space in the buffer for `needed` bytes.
    /// Try to compact the buffer, i.e., discard unused data from the front.
    /// Returns an error if the buffer is still too small.
    pub fn ensure_space(&mut self, needed: usize) -> Result<(), TlsError> {
        let remaining_space = self.buf.len() - self.tail;

        if remaining_space >= needed {
            return Ok(());
        }

        self.compact();

        let remaining_space_after_compact = self.buf.len() - self.tail;
        if remaining_space_after_compact < needed {
            return Err(TlsError::BufferTooSmall);
        }

        Ok(())
    }

    /// Discard n bytes from the start of the used buffer.
    pub fn move_head(&mut self, n: usize) {
        // fixme: should we return an error if n > tail?
        self.head += n;
        if self.head > self.tail {
            self.head = self.tail; // Prevent discarding more than tail
        }
    }

    /// Compact the buffer by moving the used data to the front and adjusting head and tail pointers
    fn compact(&mut self) {
        if self.head == 0 {
            return;
        }
        log::info!(
            "Compacting buffer, tail: {}, discarding: {}",
            self.tail,
            self.head
        );
        self.buf.copy_within(self.head..self.tail, 0);
        self.tail -= self.head;
        self.head = 0;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tls_buffer_creation() {
        let tls_buffer = TlsBuffer::new(1024);
        assert_eq!(tls_buffer.buf.len(), 1024);
        assert_eq!(tls_buffer.head, 0);
        assert_eq!(tls_buffer.tail, 0);
    }

    #[test]
    fn test_tls_buffer_move_tail() {
        let mut tls_buffer = TlsBuffer::new(10);
        tls_buffer.advance_used(3).expect("Advance used failed");
        assert_eq!(tls_buffer.tail, 3);

        tls_buffer
            .advance_used(100)
            .expect_err("Expected error for advancing beyond buffer size");
        assert_eq!(tls_buffer.tail, 3); // tail should remain unchanged
    }

    #[test]
    fn test_tls_buffer_move_head() {
        let mut tls_buffer = TlsBuffer::new(10);
        tls_buffer.advance_used(10).expect("Tail advance failed");

        tls_buffer.move_head(2);
        assert_eq!(tls_buffer.head, 2);
        tls_buffer.move_head(5);
        assert_eq!(tls_buffer.head, 7);
        tls_buffer.move_head(5); // move beyond tail
        assert_eq!(tls_buffer.head, 10); // head should not exceed tail
    }

    #[test]
    fn test_tls_buffer_compact() {
        let mut tls_buffer = TlsBuffer::new(10);
        tls_buffer.buf[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        tls_buffer.head = 2;
        tls_buffer.tail = 5;
        tls_buffer.compact();
        assert_eq!(tls_buffer.head, 0);
        assert_eq!(tls_buffer.tail, 3);
        assert_eq!(&tls_buffer.buf[..3], &[3, 4, 5]);
    }

    #[test]
    fn test_tls_buffer_ensure_space() {
        let mut tls_buffer = TlsBuffer::new(10);

        tls_buffer
            .ensure_space(5)
            .expect("Should have enough space");
        assert_eq!(tls_buffer.tail, 0);
        assert_eq!(tls_buffer.head, 0);

        tls_buffer.advance_used(5).expect("Tail advance failed");

        tls_buffer
            .ensure_space(6)
            .expect_err("Should not have enough space");

        tls_buffer.move_head(3);
        tls_buffer
            .ensure_space(6)
            .expect("Should have enough space after compacting");
    }

    #[test]
    fn test_tls_buffer_check_record_fields() {
        let mut tls_buffer = TlsBuffer::new(10);
        // Example TLS record header: ContentType=0x16 (handshake), Version=0x0303 (TLS 1.2), Length=0x0010 (16)
        tls_buffer.buf[..5].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x10]);

        let record_len = tls_buffer
            .extract_record_len_from_current_position()
            .expect("Extract record length failed");
        assert_eq!(record_len, 16);

        // Test with invalid content type
        tls_buffer.buf[..5].copy_from_slice(&[0xFF, 0x03, 0x03, 0x00, 0x10]);
        let err = tls_buffer
            .extract_record_len_from_current_position()
            .expect_err("Expected error for invalid content type");
        match err {
            TlsError::InvalidContentType => {}
            _ => panic!("Unexpected error type"),
        }
        // Test with invalid version
        tls_buffer.buf[..5].copy_from_slice(&[0x16, 0xFF, 0xFF, 0x00, 0x10]);
        let err = tls_buffer
            .extract_record_len_from_current_position()
            .expect_err("Expected error for invalid version");
        match err {
            TlsError::InvalidRecordVersion => {}
            _ => panic!("Unexpected error type"),
        }

        // Test with invalid length
        tls_buffer.buf[..5].copy_from_slice(&[0x16, 0x03, 0x03, 0xFF, 0xFF]);
        let err = tls_buffer
            .extract_record_len_from_current_position()
            .expect_err("Expected error for invalid length");
        match err {
            TlsError::InvalidRecordLength => {}
            _ => panic!("Unexpected error type"),
        }
    }
}
