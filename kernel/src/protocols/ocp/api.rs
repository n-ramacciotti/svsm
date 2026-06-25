// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

use super::source::{OcpObjectDetails, OcpSource};
use crate::{address::PhysAddr, protocols::errors::SvsmReqError};
use core::fmt::Debug;

/// Operations required for an OCP object
pub trait OcpObjectOperations: Debug + Send + Sync {
    fn read(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn write(
        &self,
        _offset: u32,
        _gpa: PhysAddr,
        _size: u32,
        _sub_index: u32,
    ) -> Result<u32, SvsmReqError> {
        Err(SvsmReqError::unsupported_call())
    }
    fn get_object_details(&self) -> &OcpObjectDetails;
    fn get_object_sources(&self) -> &[OcpSource];
}
