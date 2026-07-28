// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use crate::locking::RWLock;
use alloc::{sync::Arc, vec::Vec};

use super::api::OcpObjectOperations;

use crate::{
    address::{Address, PhysAddr},
    mm::ptguards::PerCPUPageMappingGuard,
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
};

use super::source::{OCP_NAME_LEN, OCP_SOURCE_SIZE, OcpSource};

use core::{ffi::CStr, str};

// OCP protocol services
const SVSM_OCP_LIST: u32 = 0;
const SVSM_OCP_READ: u32 = 1;
const SVSM_OCP_WRITE: u32 = 2;

const LOW_32_BITS: u64 = 0xffff_ffff;
const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

// Min and Max supported protocol version
pub const OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MIN: u32 = 1;
pub const OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MAX: u32 = 1;

static OCP_SOURCES: RWLock<Vec<Arc<dyn OcpObjectOperations>>> = RWLock::new(Vec::new());

pub fn add_ocp_object(object: Arc<dyn OcpObjectOperations>) {
    // todo: check unique name here
    let mut map = OCP_SOURCES.lock_write();
    map.push(object);
}

pub fn get_ocp_object(name: &str) -> Option<Arc<dyn OcpObjectOperations>> {
    let map = OCP_SOURCES.lock_read();
    for obj in map.iter() {
        if obj.get_object_name() == name {
            return Some(obj.clone());
        }
    }
    None
}

fn ocp_list_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_name = PhysAddr::from(params.rcx);

    let buffer_size = (params.r8 & LOW_32_BITS) as usize;

    if buffer_size == 0 || buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    if !buffer_size.is_multiple_of(OCP_SOURCE_SIZE) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let num_entries = buffer_size / OCP_SOURCE_SIZE;

    let guard = PerCPUPageMappingGuard::create(
        gpa_buffer.page_align(),
        gpa_buffer
            .checked_add(buffer_size)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let entries_ptr = guard.guest_slice::<OcpSource>(gpa_buffer.page_offset(), num_entries)?;

    let (bytes_written, max_buffer) = if gpa_name.is_null() {
        let mut entries_written = 0;

        let objects = OCP_SOURCES.lock_read();
        let objects_len = objects.len();

        for entry in objects.iter() {
            if entries_written >= num_entries {
                break;
            }

            if entries_ptr
                .write(entries_written, entry.get_object_details())
                .is_err()
            {
                break;
            }
            entries_written += 1;
        }

        (
            entries_written * OCP_SOURCE_SIZE,
            objects_len * OCP_SOURCE_SIZE,
        )
    } else {
        let mut name_slice = [0u8; OCP_NAME_LEN];
        let name_guard = PerCPUPageMappingGuard::create(
            gpa_name.page_align(),
            gpa_name
                .checked_add(OCP_NAME_LEN)
                .ok_or(SvsmReqError::invalid_address())?
                .page_align_up(),
            0,
        )?;
        let name_ptr = name_guard.guest_slice::<u8>(gpa_name.page_offset(), OCP_NAME_LEN)?;
        name_ptr.read_to_slice(&mut name_slice)?;
        let obj_name = CStr::from_bytes_until_nul(&name_slice)
            .map_err(|_| SvsmReqError::invalid_parameter())?
            .to_str()
            .map_err(|_| SvsmReqError::invalid_parameter())?;

        let Some(object) = get_ocp_object(obj_name) else {
            return Err(SvsmReqError::invalid_parameter());
        };

        let sources_len = object.get_object_source_count();

        let mut entries_written = 0;

        for entry in object.get_object_sources() {
            if entries_written >= num_entries {
                break;
            }

            if entries_ptr
                .write(entries_written, entry.get_source_details())
                .is_err()
            {
                break;
            }
            entries_written += 1;
        }
        (
            entries_written * OCP_SOURCE_SIZE,
            sources_len * OCP_SOURCE_SIZE,
        )
    };

    params.r8 = bytes_written as u64;
    params.r9 = max_buffer as u64;

    Ok(())
}

fn extract_obj_and_source_names(buffer: &[u8]) -> Result<(&str, &str), SvsmReqError> {
    let ocp_id =
        CStr::from_bytes_until_nul(buffer).map_err(|_| SvsmReqError::invalid_parameter())?;

    let bytes = ocp_id.to_bytes();

    let slash_pos = bytes
        .iter()
        .position(|&c| c == b'/')
        .ok_or(SvsmReqError::invalid_parameter())?;

    let obj_name =
        str::from_utf8(&bytes[..slash_pos]).map_err(|_| SvsmReqError::invalid_parameter())?;

    let source_name =
        str::from_utf8(&bytes[slash_pos + 1..]).map_err(|_| SvsmReqError::invalid_parameter())?;

    Ok((obj_name, source_name))
}

fn ocp_read_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_id = PhysAddr::from(params.rcx);
    let bytes_to_read = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if bytes_to_read as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let mut id_slice = [0u8; OCP_NAME_LEN * 2];

    let id_guard = PerCPUPageMappingGuard::create(
        gpa_id.page_align(),
        gpa_id
            .checked_add(OCP_NAME_LEN * 2)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;
    let id_ptr = id_guard.guest_slice::<u8>(gpa_id.page_offset(), OCP_NAME_LEN * 2)?;
    id_ptr.read_to_slice(&mut id_slice)?;

    let (obj_name, source_name) = extract_obj_and_source_names(&id_slice)?;

    let Some(object) = get_ocp_object(obj_name) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    if bytes_to_read == 0 {
        params.r8 = 0;
        return Ok(());
    }

    let bytes_copied = object.read(offset, gpa_buffer, bytes_to_read, source_name)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

fn ocp_write_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let gpa_id = PhysAddr::from(params.rcx);
    let bytes_to_write = (params.r8 & LOW_32_BITS) as u32;
    let offset = (params.r9 & LOW_32_BITS) as u32;

    if bytes_to_write as usize > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let mut id_slice = [0u8; OCP_NAME_LEN * 2];

    let id_guard = PerCPUPageMappingGuard::create(
        gpa_id.page_align(),
        gpa_id
            .checked_add(OCP_NAME_LEN * 2)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;
    let id_ptr = id_guard.guest_slice::<u8>(gpa_id.page_offset(), OCP_NAME_LEN * 2)?;
    id_ptr.read_to_slice(&mut id_slice)?;

    let (obj_name, source_name) = extract_obj_and_source_names(&id_slice)?;

    let Some(object) = get_ocp_object(obj_name) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    let bytes_copied = object.write(offset, gpa_buffer, bytes_to_write, source_name)?;

    params.r8 = bytes_copied as u64;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST => ocp_list_request(params),
        SVSM_OCP_READ => ocp_read_request(params),
        SVSM_OCP_WRITE => ocp_write_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
