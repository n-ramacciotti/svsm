// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use super::source::OcpSource;

use crate::{address::PhysAddr, protocols::errors::SvsmReqError};

use alloc::sync::Arc;
use core::{fmt::Debug, slice::Iter};

/// Operations required for an OCP object
pub trait OcpObjectOperations: Debug + Send + Sync {
    fn read(&self, offset: u32, gpa: PhysAddr, size: u32, name: &str) -> Result<u32, SvsmReqError> {
        let Some(source) = self.get_object_source_by_name(name) else {
            return Err(SvsmReqError::invalid_parameter());
        };
        // todo: check if offset is valid for the source here or delegate to the source read method?
        source.read(offset, gpa, size)
    }
    fn write(
        &self,
        offset: u32,
        gpa: PhysAddr,
        size: u32,
        name: &str,
    ) -> Result<u32, SvsmReqError> {
        let Some(source) = self.get_object_source_by_name(name) else {
            return Err(SvsmReqError::invalid_parameter());
        };
        // todo: check if the source is writable here or delegate?
        // todo: check if offset is valid here or delegate?
        source.write(offset, gpa, size)
    }
    fn get_object_name(&self) -> &str;
    fn get_object_details(&self) -> &OcpSource;
    fn get_object_source_by_name(&self, name: &str) -> Option<Arc<dyn OcpSourceOperations>>;
    // todo: change return type of get_object_sources
    fn get_object_sources(&self) -> Iter<'_, Arc<dyn OcpSourceOperations>>;
    fn get_object_source_count(&self) -> usize;
}

/// Operations required for an OCP source
pub trait OcpSourceOperations: Debug + Send + Sync {
    fn read(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn write(&self, _offset: u32, _gpa: PhysAddr, _size: u32) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }

    fn get_source_details(&self) -> &OcpSource;
}
