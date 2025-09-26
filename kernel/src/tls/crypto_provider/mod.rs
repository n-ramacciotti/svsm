// SPDX-License-Identifier: MIT
//
// Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com>
//
// Derived from the crypto-provider example in rustls (https://github.com/rustls/rustls/tree/main/provider-example)

extern crate alloc;
use alloc::sync::Arc;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;

mod aead;
mod hash;
mod hmac;
mod kx;
mod sign;
mod verify;

/// Returns a `CryptoProvider` that supports a limited set of cryptographic operations.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

// The following is a RNG based on the cocoon_tpm_crypto crate. There is also a better version in
// https://github.com/coconut-svsm/svsm/pull/806
// For the moment, we use the OsRng from rand_core as a placeholder.
// use cocoon_tpm_crypto::rng::ChainedRng;
// use cocoon_tpm_crypto::rng::{test_rng, RngCore, X86RdSeedRng};
// use cocoon_tpm_crypto::EmptyCryptoIoSlices;
// use cocoon_tpm_utils_common::io_slices::{self, IoSlicesIterCommon};

// #[derive(Debug)]
// struct Provider;

// impl rustls::crypto::SecureRandom for Provider {
//     fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
//         let parent_rng =
//             X86RdSeedRng::instantiate().map_err(|_| rustls::crypto::GetRandomFailed)?;
//         let child_rng = test_rng();

//         let mut chained_rng = ChainedRng::chain(parent_rng, child_rng);

//         chained_rng
//             .generate(
//                 io_slices::SingletonIoSliceMut::new(bytes).map_infallible_err(),
//                 None::<EmptyCryptoIoSlices>,
//             )
//             .map_err(|_| rustls::crypto::GetRandomFailed)
//     }
// }

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Ok(Arc::new(
            sign::EcdsaSigningKeyP256::try_from(key_der)
                .map_err(|err| rustls::Error::General(alloc::format!("{}", err)))?,
        ))
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[rustls::SupportedCipherSuite::Tls13(
    &rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        //protocol_version: rustls::version::TLS13_VERSION,
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Aes128Gcm,
        quic: None,
    },
)];
