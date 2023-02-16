// Build script

use cargo_spec::build::{self, OutputFormat};

fn main() {
    // Rebuild specification
    build::build(
        "../book/specifications/kimchi/Specification.toml".into(),
        Some("../book/src/specs/kimchi.md".into()),
        OutputFormat::Markdown,
    )
    .expect("failed to generate specification");
}