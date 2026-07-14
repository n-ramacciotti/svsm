// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use crate::{
    address::{Address, PhysAddr},
    mm::{GuestPtr, PerCPUPageMappingGuard, valid_phys_region},
    protocols::{RequestParams, errors::SvsmReqError},
    types::PAGE_SIZE,
    utils::MemoryRegion,
};

use super::map::explore_map;
use super::source::{OCP_SOURCE_DETAILS_SIZE, OcpObjectDetails};

// OCP protocol services
const SVSM_OCP_LIST_OBJECTS: u32 = 0;

const LOW_32_BITS: u64 = 0xffff_ffff;
const OCP_BUFFER_MAX_SIZE: usize = PAGE_SIZE;
const OCP_BUFFER_ALIGNMENT: usize = 8;

fn ocp_list_objects_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let gpa_buffer = PhysAddr::from(params.rdx);

    if !gpa_buffer.is_aligned(OCP_BUFFER_ALIGNMENT) {
        return Err(SvsmReqError::invalid_address());
    }

    let num_entries = (params.r8 & LOW_32_BITS) as usize;
    let first = (params.rcx & LOW_32_BITS) as usize;

    if num_entries == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    // Real buffer size is not inside request params, so
    // compute it based on the number of entries and
    // the size of each entry
    let buffer_size = num_entries * OCP_SOURCE_DETAILS_SIZE;

    if buffer_size > OCP_BUFFER_MAX_SIZE {
        return Err(SvsmReqError::invalid_parameter());
    }

    let region =
        MemoryRegion::checked_new(gpa_buffer, buffer_size).ok_or(SvsmReqError::invalid_address())?;
    if !valid_phys_region(&region) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let base_paddr = gpa_buffer.page_align();
    let offset = gpa_buffer.page_offset();
    let end_paddr = region.end().page_align_up();

    let guard = PerCPUPageMappingGuard::create(base_paddr, end_paddr, 0)?;
    let base_vaddr = guard.virt_addr();

    let mut guest_entry = GuestPtr::<OcpObjectDetails>::new(base_vaddr + offset);

    let mut entries_to_return = 0;

    for (i, entry) in explore_map(first as u32, num_entries as u32)
        .iter()
        .enumerate()
    {
        // SAFETY: guest_entry is obtained from an untrusted GPA.
        // The address is checked using with valid_phys_region()
        // to ensure it is not assigned to SVSM.
        if unsafe { guest_entry.write_ref(entry.get_object_details()) }.is_err() {
            // fixme: is it correct that the write can fail mid loop
            // and some entries have already been written?
            entries_to_return = i;
            break;
        }
        guest_entry = guest_entry.offset(1);
    }

    params.rcx = entries_to_return as u64;

    Ok(())
}

pub fn ocp_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_OCP_LIST_OBJECTS => ocp_list_objects_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
