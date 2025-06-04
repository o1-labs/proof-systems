use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    env,
    ffi::OsString,
    ops::{Deref, DerefMut},
    path::PathBuf,
    process::Command,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build WASM package
    BuildWasm {
        /// Output directory for wasm-pack
        #[arg(long, required = true)]
        out_dir: String,

        /// Target platform (nodejs or web)
        #[arg(long, required = true, value_enum)]
        target: Target,

        /// Version of `rustc`
        #[arg(long)]
        rust_version: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Target {
    /// Build for NodeJS
    Nodejs,
    /// Build for Web
    Web,
}

impl From<Target> for &'static str {
    fn from(target: Target) -> &'static str {
        match target {
            Target::Nodejs => "nodejs",
            Target::Web => "web",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::BuildWasm {
            out_dir,
            target,
            rust_version,
        } => build_wasm(out_dir, *target, rust_version.as_deref()),
    }
}

type RustVersion<'a> = Option<&'a str>;

fn build_wasm(out_dir: &str, target: Target, rust_version: RustVersion) -> Result<()> {
    const RUSTFLAGS: &str = "-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--max-memory=4294967296";

    let cargo_target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let artifact_dir = PathBuf::from(format!("{cargo_target_dir}/bin"));

    let mut cmd = RustVersionCommand::for_cargo(rust_version);

    let args = [
        "build",
        "--release",
        "--package=wasm-pack",
        "--bin=wasm-pack",
        "--artifact-dir",
        artifact_dir.to_str().unwrap(),
        "-Z=unstable-options",
    ];

    let status = cmd
        .args(args)
        .env("CARGO_TARGET_DIR", &cargo_target_dir)
        .status()
        .context("Failed to build wasm-pack")?;

    if !status.success() {
        anyhow::bail!("wasm-pack build failed");
    }

    let wasm_pack_path = artifact_dir.join("wasm-pack");
    let mut cmd = RustVersionCommand::for_wasm_pack(wasm_pack_path, rust_version);

    // Prepare the command arguments
    let args = [
        "build",
        "--target",
        target.into(),
        "--out-dir",
        out_dir,
        "plonk-wasm",
        "--",
        "-Z",
        "build-std=panic_abort,std",
    ];

    let target_args: &[_] = if target == Target::Nodejs {
        &["--features", "nodejs"]
    } else {
        &[]
    };

    let status = cmd
        .args(args)
        .args(target_args)
        .env("RUSTFLAGS", RUSTFLAGS)
        .status()
        .context("Failed to execute wasm-pack")?;

    if !status.success() {
        anyhow::bail!("wasm-pack build for {} failed", <&str>::from(target));
    }

    Ok(())
}

struct RustVersionCommand<'a> {
    cmd: Command,
    rustup_args: Option<(OsString, &'a str)>,
}

impl<'a> RustVersionCommand<'a> {
    fn for_cargo(rustup_args: Option<&'a str>) -> Self {
        let (cmd, rustup_args) = if let Some(version) = rustup_args {
            (
                Command::new("rustup"),
                Some((OsString::from("cargo"), version)),
            )
        } else {
            (Command::new("cargo"), None)
        };

        Self { cmd, rustup_args }
    }

    fn for_wasm_pack(wasm_path: PathBuf, rustup_args: Option<&'a str>) -> Self {
        let (cmd, rustup_args) = if let Some(version) = rustup_args {
            let cmd = Command::new("rustup");
            let rustup_args = Some((wasm_path.into_os_string(), version));

            (cmd, rustup_args)
        } else {
            (Command::new(wasm_path), None)
        };

        Self { cmd, rustup_args }
    }
}

impl Deref for RustVersionCommand<'_> {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.cmd
    }
}

impl DerefMut for RustVersionCommand<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let Some((program, version)) = self.rustup_args.take() else {
            return &mut self.cmd;
        };

        self.cmd.arg("run").arg(version).arg(program)
    }
}
