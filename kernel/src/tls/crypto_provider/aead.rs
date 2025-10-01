// SPDX-License-Identifier: MIT
//
// Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com>
//
// Derived from the crypto-provider example in rustls (https://github.com/rustls/rustls/tree/main/provider-example)

extern crate alloc;
use alloc::boxed::Box;

use rustls::{
    crypto::cipher::{
        make_tls13_aad, AeadKey, BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, Iv,
        MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage,
        PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError,
    },
    ConnectionTrafficSecrets, ContentType, ProtocolVersion,
};

use aes_gcm::{
    aead::{AeadInPlace, Buffer, Result as AeadResult},
    KeyInit, KeySizeUser,
};

pub(crate) struct Aes128Gcm;

impl Tls13AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(
            aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(
            aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        ))
    }

    fn key_len(&self) -> usize {
        aes_gcm::Aes128Gcm::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

const AES_GCM_OVERHEAD: usize = 16;
struct Tls13Cipher(aes_gcm::Aes128Gcm, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.1, seq);
        let nonce = aes_gcm::Nonce::from(nonce.0);

        let aad = make_tls13_aad(total_len);

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| {
                OutboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + AES_GCM_OVERHEAD + 1
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload;

        let nonce = Nonce::new(&self.1, seq);
        let nonce = aes_gcm::Nonce::from(nonce.0);

        let aad = make_tls13_aad(payload.len());

        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        msg.into_tls13_unpadded_message()
    }
}

struct EncryptBufferAdapter<'a>(&'a mut PrefixedPayload);

impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> AeadResult<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

struct DecryptBufferAdapter<'a, 'p>(&'a mut BorrowedPayload<'p>);

impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}

impl Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> AeadResult<()> {
        unreachable!("not used by `AeadInPlace::decrypt_in_place`")
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}
