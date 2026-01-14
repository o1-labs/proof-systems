use std::{path::PathBuf, process::Command};

#[test]
fn test_arrabbiata_binary() {
    // Build the binary path
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let build_mode = "release";

    // Build the path to the binary. It is assumed that no package is selected
    // when running the test, i.e. no `-p arrabbiata` in the `cargo test`
    // command. It is the behavior in the CI.
    let binary_path = project_root
        .join("..")
        .join("target")
        .join(build_mode)
        .join("arrabbiata");
    println!("Executing binary {:?}", binary_path);

    // Build the command
    let output = Command::new(binary_path)
        .arg("execute")
        .arg("--circuit")
        .arg("squaring")
        .arg("-n")
        .arg("10")
        .arg("--srs-size")
        .arg("8")
        .output()
        .expect("Failed to execute binary");

    // Assert the test results
    assert!(
        output.status.success(),
        "Binary did not exit successfully: {:?}",
        output
    );
}
