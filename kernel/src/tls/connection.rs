//! This module is responsible for managing TLS connections.
//! It uses rustls unbuffered API, which are suitable for no_std environments.
//! The module provides a TlsClient struct to create and configure TLS connections,
//! and a TlsConnection struct to manage individual TLS connections over VsockStream.
//! The TlsConnection struct, thanks to the provided API, manages the TLS state machine,
//! including handshake, reading and writing application data, and closing the connection.

extern crate alloc;
use alloc::sync::Arc;

use super::buffer::TlsBuffer;
use super::constant::{HEADER_LEN, IN_BUF_SIZE, OUT_BUF_SIZE};
use super::crypto_provider::provider;
use super::error::TlsError;
use super::time_provider::FixedTimeProvider;

use crate::error::SvsmError;
use crate::io::{Read, Write};
use crate::vsock::virtio_vsock::VsockStream;

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::pki_types::{CertificateDer, DnsName, ServerName};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeTlsData, UnbufferedStatus, WriteTraffic,
};
use rustls::{ClientConfig, RootCertStore};

/// The [`TlsClient`] struct is responsible for creating and configuring [`TlsConnection`] instances.
#[derive(Debug)]
pub struct TlsClient {
    config: Arc<ClientConfig>,
}

impl TlsClient {
    /// Create a new [`TlsClient`] with optional debug information
    pub fn new(debug_info: bool) -> Self {
        let config =
            Self::create_client_config(debug_info).expect("Failed to create TLS client config");
        Self { config }
    }

    /// Establish a TLS connection over a given [`VsockStream`]
    pub fn connect(
        &self,
        sock: VsockStream,
        server_name: &str,
    ) -> Result<TlsConnection, SvsmError> {
        let conn = UnbufferedClientConnection::new(
            self.config.clone(),
            Self::server_name_from_str(server_name)?,
        )
        .map_err(TlsError::from)?;
        Ok(TlsConnection::new(sock, conn))
    }

    /// Create a TLS client configuration, which includes setting up root certificates, a time provider, and a crypto provider.
    fn create_client_config(debug_info: bool) -> Result<Arc<ClientConfig>, TlsError> {
        let crypto_provider = provider();
        let time_provider = FixedTimeProvider::december_2025();

        let mut root_store = RootCertStore::empty();

        root_store.add(CertificateDer::from_slice(include_bytes!(
            "../../../certificates/ca.der"
        )))?;

        let mut config =
            ClientConfig::builder_with_details(Arc::new(crypto_provider), Arc::new(time_provider))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(root_store)
                .with_no_client_auth();

        if debug_info {
            config.key_log = Arc::new(super::key_logger::MyKeyLogger);
        }

        Ok(Arc::new(config))
    }

    /// Convert a string to a [`ServerName`]
    fn server_name_from_str(name: &str) -> Result<ServerName<'static>, TlsError> {
        let dns = DnsName::try_from(name).map_err(|_| TlsError::InvalidDnsName)?;
        Ok(ServerName::DnsName(dns.to_owned()))
    }
}

/// The [`TlsConnection`] struct manages a TLS connection over a [`VsockStream`].
/// It provides a way to manage all the TLS-related operations.
pub struct TlsConnection {
    conn: UnbufferedClientConnection,
    sock: VsockStream,
    in_buffer: TlsBuffer,
    out_buffer: TlsBuffer,
    status: ConnectionDetails,
}

impl TlsConnection {
    /// Create a new [`TlsConnection`]
    pub fn new(sock: VsockStream, conn: UnbufferedClientConnection) -> Self {
        let in_buffer = TlsBuffer::new(IN_BUF_SIZE);
        let out_buffer = TlsBuffer::new(OUT_BUF_SIZE);
        let status = ConnectionDetails::new();
        Self {
            conn,
            sock,
            in_buffer,
            out_buffer,
            status,
        }
    }

    /// Complete the TLS handshake
    pub fn complete_handshake(&mut self) -> Result<(), SvsmError> {
        while !self.status.handshake_complete && !self.status.connection_closed {
            self.tls_state_machine_advance(TlsAction::Handshake)?;
        }
        Ok(())
    }

    /// Read a single TLS record and decrypt application data into the provided buffer
    pub fn read_tls(&mut self, buf: &mut [u8]) -> Result<usize, SvsmError> {
        let mut total_read = 0;
        if self.status.connection_closed || self.status.peer_closed {
            return Ok(0);
        }
        self.status.received_response = false; // reset for next read
        while !self.status.received_response
            && !self.status.connection_closed
            && !self.status.peer_closed
        {
            self.tls_state_machine_advance(TlsAction::ReadRecord {
                buffer: buf,
                total_read: &mut total_read,
            })?;
        }
        Ok(total_read)
    }

    /// Encrypt and send a single TLS record
    pub fn write_tls(&mut self, data: &[u8]) -> Result<(), SvsmError> {
        if self.status.connection_closed {
            return Err(TlsError::ConnectionClosed.into());
        }
        self.tls_state_machine_advance(TlsAction::WriteRecord { buffer: data })?;
        if !self.status.request_sent {
            // should return 0?
            return Err(TlsError::GenericError.into());
        }
        Ok(()) // should return buffer len?
    }

    /// Close the TLS connection
    pub fn close_tls(&mut self) -> Result<(), SvsmError> {
        while !self.status.connection_closed {
            self.tls_state_machine_advance(TlsAction::CloseConnection)?;
        }
        Ok(())
    }

    /// Advance the TLS state machine based on the current connection state and the provided action
    fn tls_state_machine_advance(&mut self, action: TlsAction<'_>) -> Result<(), SvsmError> {
        // Process incoming TLS record and determine the next state
        let UnbufferedStatus { discard, state } = self
            .conn
            .process_tls_records(self.in_buffer.curr_used_buf_as_mut());

        match state.map_err(TlsError::from)? {
            // ##################################################################
            // Handshake states
            // ##################################################################

            // An handshake record needs to be encoded
            ConnectionState::EncodeTlsData(mut encode_tls_data) => {
                if TlsAction::Handshake != action {
                    return Err(TlsError::UnexpectedState.into());
                }

                TlsConnection::prepare_handshake_record(
                    &mut encode_tls_data,
                    &mut self.out_buffer,
                )?;
                self.in_buffer.move_head(discard);
            }

            // The handshake record is ready to be transmitted
            ConnectionState::TransmitTlsData(trasmit_tls_data) => {
                if TlsAction::Handshake != action {
                    return Err(TlsError::UnexpectedState.into());
                }
                TlsConnection::send_record_over_vsock(&mut self.sock, &mut self.out_buffer)?;
                // Signal that the transmission is complete
                trasmit_tls_data.done();
                self.in_buffer.move_head(discard);
                if !self.conn.is_handshaking() {
                    self.status.handshake_complete = true;
                }
            }

            // Waiting for a handshake record from the peer
            ConnectionState::BlockedHandshake { .. } => {
                if TlsAction::Handshake != action {
                    return Err(TlsError::UnexpectedState.into());
                }
                self.in_buffer.move_head(discard);
                self.recv_record_over_vsock()?;
            }

            // ##################################################################
            // Application data states
            // ##################################################################

            // Ready to send application data, to close the connection, or to read data
            ConnectionState::WriteTraffic(mut write_traffic) => {
                if TlsAction::Handshake == action {
                    return Err(TlsError::UnexpectedState.into());
                }

                if let TlsAction::WriteRecord { buffer } = action {
                    TlsConnection::encrypt_data(&mut write_traffic, &mut self.out_buffer, buffer)?;
                    TlsConnection::send_record_over_vsock(&mut self.sock, &mut self.out_buffer)?;
                    self.status.request_sent = true;
                    self.in_buffer.move_head(discard);
                } else if TlsAction::CloseConnection == action && !self.status.our_side_closed {
                    TlsConnection::prepare_queue_close_notify(
                        &mut write_traffic,
                        &mut self.out_buffer,
                    )?;
                    TlsConnection::send_record_over_vsock(&mut self.sock, &mut self.out_buffer)?;
                    self.status.our_side_closed = true;
                    self.in_buffer.move_head(discard);
                } else {
                    log::info!("Receiving record");
                    self.in_buffer.move_head(discard);
                    self.recv_record_over_vsock()?;
                }
            }

            // Application data record ready to be read
            ConnectionState::ReadTraffic(mut read_traffic) => {
                let TlsAction::ReadRecord { buffer, total_read } = action else {
                    return Err(TlsError::UnexpectedState.into());
                };

                let res = read_traffic
                    .next_record()
                    .ok_or(TlsError::GenericError)?
                    .map_err(TlsError::from)?;

                let mut total_discard = discard;

                let AppDataRecord { discard, payload } = res;

                total_discard += discard;

                let payload_len = payload.len();
                let to_copy = core::cmp::min(buffer.len(), payload_len);
                buffer[..to_copy].copy_from_slice(&payload[..to_copy]);
                self.in_buffer.move_head(total_discard);
                self.status.received_response = true;
                *total_read += to_copy;
            }

            // The peer sent a close_notify alert
            ConnectionState::PeerClosed => {
                log::info!("Peer closed the connection");
                self.in_buffer.move_head(discard);
                self.status.peer_closed = true;
                // maybe call close_tls() here? What if I need to send more data?
            }

            // The connection is fully closed
            ConnectionState::Closed => {
                self.status.connection_closed = true;
            }

            _ => {
                return Err(TlsError::UnexpectedState.into());
            }
        }

        Ok(())
    }

    /// Encrypt application data and store it in the out_buffer
    fn encrypt_data(
        write_traffic: &mut WriteTraffic<'_, ClientConnectionData>,
        out_buffer: &mut TlsBuffer,
        data: &[u8],
    ) -> Result<(), TlsError> {
        let bytes_written = write_traffic.encrypt(data, out_buffer.remaining_buf_as_mut())?;
        out_buffer.advance_used(bytes_written)?;

        Ok(())
    }

    /// Prepare a close_notify alert to be sent over the network. From this point on, no more data can be sent.
    fn prepare_queue_close_notify(
        write_traffic: &mut WriteTraffic<'_, ClientConnectionData>,
        out_buffer: &mut TlsBuffer,
    ) -> Result<(), TlsError> {
        let bytes_written = write_traffic.queue_close_notify(out_buffer.remaining_buf_as_mut())?;
        out_buffer.advance_used(bytes_written)?;
        Ok(())
    }

    /// Prepare a TLS handshake record to be sent over the network based on the current handshake state
    fn prepare_handshake_record(
        encode_tls_data: &mut EncodeTlsData<'_, ClientConnectionData>,
        out_buffer: &mut TlsBuffer,
    ) -> Result<(), TlsError> {
        let bytes_written = encode_tls_data.encode(out_buffer.remaining_buf_as_mut())?;
        out_buffer.advance_used(bytes_written)?;
        Ok(())
    }

    /// Send the contents of the out_buffer over the [`VsockStream`] and reset the buffer
    fn send_record_over_vsock(
        sock: &mut VsockStream,
        out_buffer: &mut TlsBuffer,
    ) -> Result<(), SvsmError> {
        sock.write(out_buffer.curr_used_buf_as_ref())?;
        out_buffer.reset_used();
        Ok(())
    }

    /// Receive a TLS record from the [`VsockStream`] and store it in the in_buffer
    fn recv_record_over_vsock(&mut self) -> Result<(), SvsmError> {
        // First read the TLS record header to determine the payload length
        // Then read the payload based on the length specified in the header

        self.in_buffer.ensure_space(HEADER_LEN)?;

        let read_bytes = self
            .sock
            .read(self.in_buffer.mutable_slice_from_remaining(HEADER_LEN)?)?;

        if read_bytes != HEADER_LEN {
            return Err(TlsError::IncompleteRead.into());
        }

        let payload_len = self.in_buffer.extract_record_len_from_current_position()?;
        self.in_buffer.advance_used(HEADER_LEN)?;

        self.in_buffer.ensure_space(payload_len)?;

        let read_bytes = self
            .sock
            .read(self.in_buffer.mutable_slice_from_remaining(payload_len)?)?;

        if read_bytes != payload_len {
            return Err(TlsError::IncompleteRead.into());
        }

        self.in_buffer.advance_used(payload_len)?;

        Ok(())
    }
}

impl core::fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsConnection")
            .field("in_buffer", &self.in_buffer)
            .field("out_buffer", &self.out_buffer)
            .field("sock", &self.sock)
            .field("status", &self.status)
            .field("conn", &"UnbufferedClientConnection")
            .finish()
    }
}

impl Drop for TlsConnection {
    fn drop(&mut self) {
        // fixme: Should I move the close logic here?
        // if !self.status.connection_closed {
        //     if let Err(e) = self.close_tls() {
        //         log::error!("Error closing TLS connection: {:?}", e);
        //    }
        //}
        if let Err(e) = self.sock.close() {
            log::error!("Error closing VsockStream: {:?}", e);
        }
    }
}

/// Represents the possible actions that can be performed in the TLS state machine.
#[derive(PartialEq)]
enum TlsAction<'a> {
    Handshake,
    ReadRecord {
        buffer: &'a mut [u8],
        total_read: &'a mut usize,
    },
    WriteRecord {
        buffer: &'a [u8],
    },
    CloseConnection,
}

/// Internal struct to track the state of the TLS connection
#[derive(Debug)]
struct ConnectionDetails {
    handshake_complete: bool,
    request_sent: bool,
    received_response: bool,
    peer_closed: bool,
    our_side_closed: bool,
    connection_closed: bool,
}

impl ConnectionDetails {
    /// Create a new [`ConnectionDetails`] instance with default values
    fn new() -> Self {
        Self {
            handshake_complete: false,
            request_sent: false,
            received_response: false,
            peer_closed: false,
            our_side_closed: false,
            connection_closed: false,
        }
    }
}
