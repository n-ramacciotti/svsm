// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use crate::locking::RWLock;
use alloc::{sync::Arc, vec::Vec};

use super::api::OcpObjectOperations;

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
