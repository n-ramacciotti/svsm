/// Errors specific to TLS operations
#[derive(Clone, Copy, Debug)]
pub enum TlsError {
    HandshakeFailed,
    InvalidMessage,
    InvalidCertificate,
    EncryptError,
    DecryptError,
    NoCertificates,
    UnsupportedNameType,
    GenericError,
    ConnectionClosed,
    InvalidDnsName,
    EncodeError,
    EarlyDataError,
    FailedToGetRandomBytes,
    MaxIterationsReached,
    HandshakeNotComplete,
    UnexpectedState,
    BufferTooSmall,
    IncompleteRead,
    PeerClosed,
    RequestAlreadySent,
    ConnectionAlreadyClosed,
}

impl From<rustls::pki_types::InvalidDnsNameError> for TlsError {
    fn from(_err: rustls::pki_types::InvalidDnsNameError) -> Self {
        TlsError::InvalidDnsName
    }
}

impl From<rustls::Error> for TlsError {
    fn from(err: rustls::Error) -> Self {
        use rustls::Error::*;
        log::info!("Error from rustls: {:?}", err);
        match err {
            InappropriateMessage { .. } => TlsError::InvalidMessage,
            InappropriateHandshakeMessage { .. } => TlsError::HandshakeFailed,
            InvalidEncryptedClientHello(_) => TlsError::HandshakeFailed,
            InvalidMessage(_) => TlsError::InvalidMessage,
            NoCertificatesPresented => TlsError::NoCertificates,
            UnsupportedNameType => TlsError::UnsupportedNameType,
            DecryptError => TlsError::DecryptError,
            EncryptError => TlsError::EncryptError,
            PeerIncompatible(_) | PeerMisbehaved(_) | HandshakeNotComplete => {
                TlsError::HandshakeFailed
            }
            InvalidCertificate(_) | InvalidCertRevocationList(_) => TlsError::InvalidCertificate,
            General(_) => TlsError::GenericError,
            FailedToGetCurrentTime => TlsError::GenericError,
            FailedToGetRandomBytes => TlsError::FailedToGetRandomBytes,
            PeerSentOversizedRecord | NoApplicationProtocol | BadMaxFragmentSize => {
                TlsError::HandshakeFailed
            }
            AlertReceived(_) => TlsError::ConnectionClosed,
            InconsistentKeys(_) => TlsError::HandshakeFailed,
            Other(_) => TlsError::GenericError,
            _ => TlsError::GenericError,
        }
    }
}

impl From<rustls::unbuffered::EncodeError> for TlsError {
    fn from(_err: rustls::unbuffered::EncodeError) -> Self {
        TlsError::EncodeError
    }
}

impl From<rustls::unbuffered::EncryptError> for TlsError {
    fn from(_err: rustls::unbuffered::EncryptError) -> Self {
        TlsError::EncryptError
    }
}
