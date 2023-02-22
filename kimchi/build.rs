// Build script

use cargo_spec::build::{self, OutputFormat};
use std::{env, path::PathBuf};

fn main() {
    // Rebuild specification
    let manifest_path = env::var("CARGO_MANIFEST_DIR").expect("failed to get manifest path");
    let spec_path: PathBuf = [
        manifest_path.clone(),
        "../book/specifications/kimchi/Specification.toml".into(),
    ]
    .iter()
    .collect();
    let output_path: PathBuf = [manifest_path, "../book/src/specs/kimchi.md".into()]
        .iter()
        .collect();

    let files_to_watch = build::build(spec_path, Some(output_path), OutputFormat::Markdown)
        .expect("failed to generate specification");

    for file in files_to_watch {
        println!("cargo:rerun-if-changed={}", file.display());
    }
}
