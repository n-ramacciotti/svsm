// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::ipi::wait_for_ipi_block;
use crate::cpu::percpu::{this_cpu, PERCPU_AREAS};
use crate::protocols::apic::apic_protocol_request;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::protocols::reboot::reboot_protocol_request;
use crate::task::{go_idle, set_affinity, start_kernel_thread, KernelThreadStartInfo};
use crate::vmm::{enter_guest, GuestExitMessage, GuestRegister};

use crate::protocols::attest::attest_protocol_request;
#[cfg(all(feature = "vtpm", not(test)))]
use crate::protocols::{vtpm::vtpm_protocol_request, SVSM_VTPM_PROTOCOL};
use crate::protocols::{
    RequestParams, SVSM_APIC_PROTOCOL, SVSM_ATTEST_PROTOCOL, SVSM_CORE_PROTOCOL,
    SVSM_REBOOT_PROTOCOL,
};

use alloc::vec::Vec;

#[cfg(feature = "svsm-remote-console")]
use crate::https::{
    connection::{HttpsConnection, HttpsPeer},
    http::response::HttpResponseBuilder,
};
#[cfg(feature = "svsm-remote-console")]
use crate::vsock::stream::VsockStream;

/// The SVSM Calling Area (CAA)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SvsmCaa {
    call_pending: u8,
    mem_available: u8,
    pub no_eoi_required: u8,
    _rsvd: [u8; 5],
}

impl SvsmCaa {
    /// Indicates whether the `call_pending` flag is set.
    #[inline]
    pub fn call_pending(&self) -> bool {
        self.call_pending != 0
    }

    /// Returns a copy of the this CAA with the `call_pending` field cleared.
    #[inline]
    pub const fn serviced(self) -> Self {
        Self {
            call_pending: 0,
            ..self
        }
    }

    /// Returns a copy of the this CAA with the `no_eoi_required` flag updated
    #[inline]
    pub const fn update_no_eoi_required(self, no_eoi_required: u8) -> Self {
        Self {
            no_eoi_required,
            ..self
        }
    }

    /// A CAA with all of its fields set to zero.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            call_pending: 0,
            mem_available: 0,
            no_eoi_required: 0,
            _rsvd: [0; 5],
        }
    }
}

const _: () = assert!(core::mem::size_of::<SvsmCaa>() == 8);

fn request_loop_once(
    params: &mut RequestParams,
    protocol: u32,
    request: u32,
) -> Result<(), SvsmReqError> {
    match protocol {
        SVSM_CORE_PROTOCOL => core_protocol_request(request, params),
        SVSM_ATTEST_PROTOCOL => attest_protocol_request(request, params),
        #[cfg(all(feature = "vtpm", not(test)))]
        SVSM_VTPM_PROTOCOL => vtpm_protocol_request(request, params),
        SVSM_APIC_PROTOCOL => apic_protocol_request(request, params),
        SVSM_REBOOT_PROTOCOL => reboot_protocol_request(request, params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

pub fn request_loop_start(_: usize) {
    // This should always be started on the BSP.
    debug_assert_eq!(this_cpu().get_cpu_index(), 0);

    // Start an additional request loop task for each other processor in the
    // system.
    let cpu_count = PERCPU_AREAS.len();
    for task_index in 1..cpu_count {
        start_kernel_thread(KernelThreadStartInfo::new(request_loop_main, task_index))
            .expect("Failed to launch request loop thread");
    }

    // Enter the main processing loop for the BSP.
    request_loop_main(0);
}

fn request_loop_main(cpu_index: usize) {
    // Send this task to the correct CPU.
    set_affinity(cpu_index);

    log::info!("Launching request-processing task on CPU {}", cpu_index);

    // Suppress the use of IPIs before entering the guest, and ensure that all
    // other CPUs have done the same.
    wait_for_ipi_block();

    #[cfg(feature = "svsm-remote-console")]
    {
        let cpu_count = PERCPU_AREAS.len();
        if cpu_count > 1 && cpu_index == cpu_count - 1 {
            svsm_remote_console_server(cpu_index);
            log::info!("Remote console server on CPU {} exiting", cpu_index);
            return;
        }
    }

    let mut guest_regs = Vec::<GuestRegister>::new();

    loop {
        // Attempt to enter the guest.  Once registers have been set, reset the
        // vector so they are not set again.
        let msg = enter_guest(guest_regs.as_slice());
        guest_regs = Vec::new();

        match msg {
            GuestExitMessage::NoMappings => {
                log::debug!("No VMSA or CAA! Halting");
                go_idle();
            }
            GuestExitMessage::Svsm((protocol, request, mut params)) => {
                guest_regs = process_request(protocol, request, &mut params);
            }
        }
    }
}

fn process_request(protocol: u32, request: u32, params: &mut RequestParams) -> Vec<GuestRegister> {
    let rax: Option<u64> = match request_loop_once(params, protocol, request) {
        Ok(()) => Some(SvsmResultCode::SUCCESS.into()),
        Err(SvsmReqError::RequestError(code)) => {
            log::debug!(
                "Soft error handling protocol {} request {}: {:?}",
                protocol,
                request,
                code
            );
            Some(code.into())
        }
        Err(SvsmReqError::FatalError(err)) => {
            panic!(
                "Fatal error handling core protocol request {}: {:?}",
                request, err
            );
        }
    };

    // Generate vector of registers to update.
    let mut guest_regs = Vec::<GuestRegister>::new();
    if let Some(val) = rax {
        guest_regs.push(GuestRegister::X64Rax(val));
    }

    params.capture(&mut guest_regs);

    guest_regs
}

#[cfg(feature = "svsm-remote-console")]
fn serve_request_loop(https_connection: &mut HttpsConnection) {
    loop {
        let request = https_connection
            .receive_request()
            .expect("Failed to receive HTTP request");
        log::info!("Request:\n {:?}", request);

        log::info!("Path: {}", request.path().unwrap_or("<no path>"));

        let http_response = match request.path().unwrap_or("<no path>") {
            "http://localhost/reboot" => {
                let mut status = true;

                // This function panic on native
                // GUEST_VALID is not initialized in native environment
                if let Err(e) = crate::protocols::core::invalidate_guest_pages() {
                    log::info!("Failed to invalidate guest pages: {:?}", e);
                    status = false;
                }

                // This function returns an error on native
                if let Err(e) = crate::platform::SVSM_PLATFORM.relaunch_fw() {
                    log::info!("Failed to relaunch firmware: {:?}", e);
                    status = false;
                }

                let body = if status {
                    b"Reboot command executed".to_vec()
                } else {
                    b"Reboot command failed".to_vec()
                };
                let content_length = body.len();

                HttpResponseBuilder::new()
                    .version(Some(1))
                    .code(Some(200))
                    .reason(Some("OK"))
                    .header("Content-Type", "text/html")
                    .header("Content-Length", &alloc::format!("{}", content_length))
                    .body(body)
                    .build()
                    .expect("Failed to build HTTP response")
            }
            "http://localhost/get_log" => {
                let log = crate::log_buffer::log_buffer().read_log();
                let content_length = log.len();

                HttpResponseBuilder::new()
                    .version(Some(1))
                    .code(Some(200))
                    .reason(Some("OK"))
                    .header("Content-Type", "text/html")
                    .header("Content-Length", &alloc::format!("{}", content_length))
                    .body(log.to_vec())
                    .build()
                    .expect("Failed to build HTTP response")
            }
            "http://localhost/close_connection" => {
                let body = b"Connection will be closed".to_vec();
                let content_length = body.len();

                HttpResponseBuilder::new()
                    .version(Some(1))
                    .code(Some(200))
                    .reason(Some("OK"))
                    .header("Content-Type", "text/html")
                    .header("Content-Length", &alloc::format!("{}", content_length))
                    .body(body)
                    .build()
                    .expect("Failed to build HTTP response")
            }
            _ => {
                let body = b"Unknown path".to_vec();
                let content_length = body.len();

                HttpResponseBuilder::new()
                    .version(Some(1))
                    .code(Some(404))
                    .reason(Some("Not Found"))
                    .header("Content-Type", "text/html")
                    .header("Content-Length", &alloc::format!("{}", content_length))
                    .body(body)
                    .build()
                    .expect("Failed to build HTTP response")
            }
        };

        https_connection
            .send_response(&http_response)
            .expect("Failed to send HTTP response");

        if let Some(conn_header) = request.headers().get("connection") {
            if conn_header.to_lowercase() == "close" {
                log::info!("Connection: close received, breaking the loop");
                break;
            }
        }
    }
}

#[cfg(feature = "svsm-remote-console")]
pub fn svsm_remote_console_server(cpu_index: usize) {
    log::info!("Starting remote console server on {cpu_index}");

    const IN_BUF_SIZE: usize = 16 * 1024;
    const SERVER_DNS: &str = "localhost";
    const REMOTE_PORT: u32 = 12345;
    const REMOTE_CID: u64 = 2;
    // ########################################################
    // Creating HTTPS connection
    // ########################################################
    let mut https_connection = HttpsPeer::connect(
        VsockStream::connect(REMOTE_PORT, REMOTE_CID).expect("Failed to connect to VsockStream"),
        SERVER_DNS,
        IN_BUF_SIZE * 3,
    )
    .expect("Failed to create HTTPS connection");

    serve_request_loop(&mut https_connection);

    // ########################################################
    // Closing HTTPS connection
    // ########################################################
    https_connection
        .close_connection()
        .expect("Failed to close HTTPS connection");
    // ########################################################
    log::info!("HTTPS conversation completed.");
}
