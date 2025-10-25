// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

fn main() {
    // Extra cfgs
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
    println!("cargo::rustc-check-cfg=cfg(test_in_svsm)");
    println!("cargo::rustc-check-cfg=cfg(verus_keep_ghost)");
    println!("cargo::rustc-check-cfg=cfg(verus_keep_ghost_body)");
    println!("cargo::rustc-check-cfg=cfg(verus_verify_core)");

    // Stage 2
    println!("cargo:rustc-link-arg-bin=stage2=-nostdlib");
    println!("cargo:rustc-link-arg-bin=stage2=--build-id=none");
    println!("cargo:rustc-link-arg-bin=stage2=-Tkernel/src/stage2.lds");
    println!("cargo:rustc-link-arg-bin=stage2=-no-pie");

    // SVSM 2
    println!("cargo:rustc-link-arg-bin=svsm=-nostdlib");
    println!("cargo:rustc-link-arg-bin=svsm=--build-id=none");
    println!("cargo:rustc-link-arg-bin=svsm=--no-relax");
    println!("cargo:rustc-link-arg-bin=svsm=-Tkernel/src/svsm.lds");
    println!("cargo:rustc-link-arg-bin=svsm=-no-pie");

    // Extra linker args for tests.
    println!("cargo:rerun-if-env-changed=LINK_TEST");
    if std::env::var("LINK_TEST").is_ok() {
        println!("cargo:rustc-cfg=test_in_svsm");
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=--build-id=none");
        println!("cargo:rustc-link-arg=--no-relax");
        println!("cargo:rustc-link-arg=-Tkernel/src/svsm.lds");
        println!("cargo:rustc-link-arg=-no-pie");
    }

    println!("cargo:rerun-if-changed=kernel/src/stage2.lds");
    println!("cargo:rerun-if-changed=kernel/src/svsm.lds");
    println!("cargo:rerun-if-changed=build.rs");
    init_verify();
    insert_ca_cert();
}

fn init_verify() {
    if cfg!(feature = "noverify") {
        println!("cargo:rustc-env=VERUS_ARGS=--no-verify");
    } else {
        let verus_args = [
            "--rlimit=1",
            "--expand-errors",
            "--multiple-errors=5",
            "--no-auto-recommends-check",
            "--trace",
            "-Z unstable-options",
        ];
        println!("cargo:rustc-env=VERUS_ARGS={}", verus_args.join(" "));
    }
}

fn insert_ca_cert() {
    if cfg!(not(feature = "tls")) {
        return;
    }

    let ca_cert_path = std::path::Path::new(std::env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get parent directory")
        .join("certificates")
        .join("ca.der");
    if ca_cert_path.exists() {
        return;
    }

    let script_path = std::path::Path::new(std::env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get parent directory")
        .join("scripts")
        .join("gen_certs.sh");

    let status = std::process::Command::new("sh")
        .arg(&script_path)
        .status()
        .expect("Failed to execute process");
    if !status.success() {
        panic!("CA cert generation script failed");
    }
}
