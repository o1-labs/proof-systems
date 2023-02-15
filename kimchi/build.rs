// build.rs

use std::process::Command;

fn main() {
    Command::new("make")
        .args(&["-C", "../book/specifications/kimchi"])
        .status()
        .expect("failed to make specification");
}
