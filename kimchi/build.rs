// Build script

use std::process::Command;

fn main() {
    // Rebuild specification
    Command::new("make")
        .args(&["-C", "../book/specifications/kimchi"])
        .status()
        .expect("failed to make specification");
}
