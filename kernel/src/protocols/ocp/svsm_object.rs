// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use release::COCONUT_VERSION;

use super::api::OcpObjectOperations;
use super::map::add_ocp_object;
use super::source::{OcpObjectDetails, OcpObjectType, OcpSource, OcpSourceType};

use crate::address::PhysAddr;
use crate::mm::guestmem::copy_slice_to_guest;
use crate::protocols::errors::SvsmReqError;

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug)]
struct OcpSvsmObject {
    ocp_source_entries: Vec<OcpSource>,
    details: OcpObjectDetails,
    state: AtomicU32,
}

impl OcpSvsmObject {
    fn new(category: OcpObjectType, sup_index: u32) -> Self {
        Self {
            ocp_source_entries: Vec::new(),
            details: OcpObjectDetails::new(category, sup_index),
            state: AtomicU32::new(0),
        }
    }

    fn add_source(&mut self, source: OcpSource) {
        // todo remove mut
        self.ocp_source_entries.push(source);
        self.details.increase_count();
    }
}

impl OcpObjectOperations for OcpSvsmObject {
    fn read(
        &self,
        offset: u32,
        gpa: PhysAddr,
        size: u32,
        sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        let bytes_read = match sub_index {
            0 => {
                // fixme: heap allocation
                let version_str = format!("{COCONUT_VERSION}\0");
                let version_bytes = version_str.as_bytes();
                let len = version_bytes.len();

                if offset as usize >= len {
                    return Ok(0);
                }

                let end = (offset as usize + size as usize).min(len);

                let bytes_to_copy = end - offset as usize;

                let version_slice = &version_bytes[offset as usize..end];

                copy_slice_to_guest(version_slice, gpa)?;

                bytes_to_copy as u32
            }
            1 => {
                // simplified read implementation for testing purposes
                let state = self.state.load(Ordering::Acquire);
                let state_bytes = state.to_le_bytes();

                copy_slice_to_guest(&state_bytes, gpa)?;

                4
            }
            _ => {
                return Err(SvsmReqError::invalid_parameter());
            }
        };

        Ok(bytes_read)
    }

    fn write(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        let bytes_written = match sub_index {
            1 => {
                // simplified write implementation for testing purposes
                let current_state = self.state.load(Ordering::Acquire);
                self.state.store(current_state + 1, Ordering::Release);
                4
            }
            _ => {
                return Err(SvsmReqError::invalid_parameter());
            }
        };
        Ok(bytes_written)
    }

    fn get_object_sources(&self) -> &[OcpSource] {
        self.ocp_source_entries.as_slice()
    }

    fn get_object_details(&self) -> &OcpObjectDetails {
        &self.details
    }
}

pub fn add_svsm_object() {
    // TODO: get first free index from an atomic counter?

    let mut svsm_obj = OcpSvsmObject::new(OcpObjectType::Svsm, 0);

    let svsm_version = OcpSource::new(0, 0, false, "svsm_version", OcpSourceType::StaticString);
    svsm_obj.add_source(svsm_version);

    let write_source = OcpSource::new(0, 1, true, "write_source", OcpSourceType::Integer);
    svsm_obj.add_source(write_source);

    add_ocp_object(0, Arc::new(svsm_obj));
}
