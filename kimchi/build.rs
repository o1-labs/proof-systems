// Build script

use std::process::Command;

fn main() {
    // Rebuild specification
    assert!(
        Command::new("make")
            .args(&["-C", "../book/specifications/kimchi", "build"])
            .status()
            .expect("failed to get status")
            .success(),
        "failed to generate specification markdown"
    );
}
