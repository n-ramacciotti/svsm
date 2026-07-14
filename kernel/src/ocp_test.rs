// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use release::COCONUT_VERSION;

use crate::protocols::ocp::api::{OcpObjectOperations, OcpSourceOperations};
use crate::protocols::ocp::requests::add_ocp_object;
use crate::protocols::ocp::source::{OcpSource, OcpSourceType};

use crate::address::PhysAddr;
use crate::fs::{FsObj, GuestBuffer, open_read};
use crate::mm::guestmem::copy_slice_to_guest;
use crate::protocols::errors::SvsmReqError;

use core::slice::Iter;

#[derive(Debug)]
struct OcpSvsmObject {
    ocp_source_entries: Vec<Arc<dyn OcpSourceOperations>>,
    details: OcpSource,
}

impl OcpSvsmObject {
    fn new() -> Self {
        Self {
            ocp_source_entries: Vec::new(),
            details: OcpSource::new_object("SVSM"),
        }
    }

    fn add_source(&mut self, source: Arc<dyn OcpSourceOperations>) {
        // todo remove mut
        self.ocp_source_entries.push(source);
    }
}

impl OcpObjectOperations for OcpSvsmObject {
    fn get_object_source_by_name(&self, name: &str) -> Option<Arc<dyn OcpSourceOperations>> {
        self.ocp_source_entries
            .iter()
            .find(|s| s.get_source_details().get_name() == name)
            .cloned()
    }

    fn get_object_sources(&self) -> Iter<'_, Arc<dyn OcpSourceOperations>> {
        self.ocp_source_entries.iter()
    }

    fn get_object_details(&self) -> &OcpSource {
        &self.details
    }

    fn get_object_name(&self) -> &str {
        self.details.get_name()
    }

    fn get_object_source_count(&self) -> usize {
        self.ocp_source_entries.len()
    }
}

#[derive(Debug)]
struct SvsmVersion {
    source: OcpSource,
    version: String,
}

impl SvsmVersion {
    fn new() -> Self {
        Self {
            source: OcpSource::new(false, "svsm_version", OcpSourceType::Bytes),
            version: format!("{COCONUT_VERSION}\0"),
        }
    }
}

impl OcpSourceOperations for SvsmVersion {
    fn get_source_details(&self) -> &OcpSource {
        &self.source
    }

    fn read(&self, offset: u32, gpa: PhysAddr, size: u32) -> Result<u32, SvsmReqError> {
        let version_bytes = self.version.as_bytes();
        let len = version_bytes.len();

        if offset as usize >= len {
            return Ok(0);
        }

        let end = (offset as usize + size as usize).min(len);

        let bytes_to_copy = end - offset as usize;

        let version_slice = &version_bytes[offset as usize..end];

        copy_slice_to_guest(version_slice, gpa)?;

        Ok(bytes_to_copy as u32)
    }
}

#[derive(Debug)]
struct LogBuffer {
    source: OcpSource,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            source: OcpSource::new(false, "log_buffer", OcpSourceType::Bytes),
        }
    }
}

impl OcpSourceOperations for LogBuffer {
    fn get_source_details(&self) -> &OcpSource {
        &self.source
    }

    fn read(&self, offset: u32, gpa: PhysAddr, size: u32) -> Result<u32, SvsmReqError> {
        let log_hanlde = open_read("Log/logfile").unwrap();
        let fs_obj = FsObj::new_file(log_hanlde);
        fs_obj.seek_abs(offset as usize)?;
        let mut buffer = GuestBuffer::new(gpa, size as usize);
        Ok(fs_obj.read_buffer(&mut buffer).map(|b| b as u32)?)
    }
}

pub fn add_svsm_object() {
    let mut svsm_obj = OcpSvsmObject::new();

    let svsm_version = SvsmVersion::new();

    svsm_obj.add_source(Arc::new(svsm_version));

    let log_buffer = LogBuffer::new();
    svsm_obj.add_source(Arc::new(log_buffer));

    add_ocp_object(Arc::new(svsm_obj));
}
