// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use bitfield_struct::bitfield;
use core::{ffi::CStr, mem};
use zerocopy::{Immutable, IntoBytes};

pub const OCP_NAME_LEN: usize = 120;
pub const OCP_SOURCE_SIZE: usize = 128;

#[bitfield(u32)]
#[derive(IntoBytes, Immutable)]
/// Flags for an OCP source.
struct OcpSourceFlags {
    writable: bool,
    #[bits(31)]
    _rsvd_31_1: u32,
}

#[repr(u16)]
#[derive(Debug, IntoBytes, Immutable)]
/// Type of data the OCP source contains.
pub enum OcpSourceType {
    Object = 0,
    Bytes = 1,
    SInteger8Bit = 2,
    SInteger16Bit = 3,
    SInteger32Bit = 4,
    SInteger64Bit = 5,
}

/// OCP source details structure.
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
pub struct OcpSource {
    /// Source flags.
    flags: OcpSourceFlags,
    /// Type of the source.
    kind: OcpSourceType,
    /// Reserved field
    _rsvd: u16,
    /// Name of the source encoded as UTF-8.
    name: [u8; OCP_NAME_LEN],
}

impl OcpSource {
    pub fn new(writable: bool, name: &str, kind: OcpSourceType) -> Self {
        let mut name_bytes = [0u8; OCP_NAME_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len();

        if len == 0 || len >= OCP_NAME_LEN {
            // Failure if the length is greater than that value as we want
            // a null terminated string.
            panic!("Name length must not be zero nor exceed {OCP_NAME_LEN} bytes");
        }

        if bytes.contains(&b'/') || bytes.contains(&b'\0') {
            panic!("Name must not contain the '/' or null characters");
        }

        name_bytes[..len].copy_from_slice(bytes);

        Self {
            kind,
            flags: OcpSourceFlags::new().with_writable(writable),
            _rsvd: 0,
            name: name_bytes,
        }
    }

    pub fn new_object(name: &str) -> Self {
        Self::new(false, name, OcpSourceType::Object)
    }

    pub fn get_name(&self) -> &str {
        let name = CStr::from_bytes_until_nul(&self.name).unwrap();
        name.to_str().unwrap_or("")
    }
}

const _: () = assert!(
    mem::offset_of!(OcpSource, flags) == 0x00
        && mem::offset_of!(OcpSource, kind) == 0x04
        && mem::offset_of!(OcpSource, _rsvd) == 0x06
        && mem::offset_of!(OcpSource, name) == 0x08
        && mem::size_of::<OcpSource>() == OCP_SOURCE_SIZE
);
