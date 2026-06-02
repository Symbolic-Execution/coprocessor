//! Smoke check that the `coprocessor-host` binary starts under local
//! configuration and exits cleanly. This is the "host can start and shut
//! down" acceptance check for the scaffold slice.

use std::process::Command;

#[test]
fn binary_starts_and_shuts_down_cleanly() {
    let binary = env!("CARGO_BIN_EXE_coprocessor-host");
    let output = Command::new(binary)
        .output()
        .expect("coprocessor-host binary must run");

    assert!(
        output.status.success(),
        "binary exited non-zero: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("configuration loaded"),
        "expected readiness message in stdout, got: {stdout}",
    );
}
