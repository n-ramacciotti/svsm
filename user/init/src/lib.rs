// SPDX-License-Identifier: MIT

#![no_std]
#![cfg_attr(
    all(test, test_in_svsm),
    no_main,
    feature(custom_test_frameworks),
    test_runner(userlib::testing::svsm_usermodule_test_runner),
    reexport_test_harness_main = "usermodule_tests_in_svsm"
)]

#[test]
fn test_nop() {}

// When running tests inside the SVSM:
// Build the crate entrypoint.
#[cfg(all(test, test_in_svsm))]
#[path = "main.rs"]
pub mod userinit;
