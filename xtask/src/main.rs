use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use raw_cpuid::CpuId;
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

    /// Build kimchi-stubs with optional CPU optimisations
    BuildKimchiStubs {
        /// Target directory for cargo build artifacts
        #[arg(long)]
        target_dir: Option<String>,

        #[arg(long, short, action, default_value_t = false)]
        offline: bool,
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
        Commands::BuildKimchiStubs {
            target_dir,
            offline,
        } => build_kimchi_stubs(target_dir.as_deref(), *offline),
    }
}

type RustVersion<'a> = Option<&'a str>;

fn build_kimchi_stubs(target_dir: Option<&str>, offline: bool) -> Result<()> {
    // Optimisations are enabled by default, but can be disabled by setting the
    // `RUST_TARGET_FEATURE_OPTIMISATIONS` environment variable to any other
    // value than "y".
    let optimisations_enabled = env::var("RUST_TARGET_FEATURE_OPTIMISATIONS")
        .map(|v| ["y", "1", "true"].contains(&v.to_lowercase().as_str()))
        .unwrap_or(true);

    #[cfg(target_arch = "x86_64")]
    let cpu_supports_adx_bmi2 = {
        let cpuid = CpuId::new();
        cpuid
            .get_extended_feature_info()
            .map_or(false, |f| f.has_adx() && f.has_bmi2())
    };
    // ADX and BMI2 are not applicable to other architectures.
    #[cfg(not(target_arch = "x86_64"))]
    let cpu_supports_adx_bmi2 = false;

    // If optimisations are enabled and the CPU supports ADX and BMI2, we enable
    // those features.
    let rustflags = match (optimisations_enabled, cpu_supports_adx_bmi2) {
        (true, true) => {
            // If optimisations are enabled and the CPU supports ADX and BMI2,
            // we enable them.
            Some("-C target-feature=+bmi2,+adx".to_string())
        }
        (false, true) => {
            // If optimisations are disabled but the CPU supports ADX and BMI2,
            // we explicitly disable them.
            Some("-C target-feature=-bmi2,-adx".to_string())
        }
        (true, false) => {
            // If the CPU does not support ADX and BMI2, we do not set any
            // target features. It could be handled in the `else` branch, but we
            // want to be explicit. If the CPU does not support these features, but
            // we still add the -bmi2 and -adx flags, it will cause a build warning
            // we want to avoid on the user console.
            None
        }
        (false, false) => None,
    };

    let target_dir = target_dir.unwrap_or("target/kimchi_stubs_build");

    let mut cmd = Command::new("cargo");
    cmd.args(&[
        "build",
        "--release",
        "-p",
        "kimchi-stubs",
        "--target-dir",
        target_dir,
    ]);

    if offline {
        cmd.arg("--offline");
    }

    if let Some(rustflags) = rustflags {
        cmd.env("RUSTFLAGS", rustflags);
    }

    let status = cmd.status().context("Failed to build kimchi-stubs")?;

    if !status.success() {
        anyhow::bail!("kimchi-stubs build failed");
    }

    Ok(())
}

fn build_wasm(out_dir: &str, target: Target, rust_version: RustVersion) -> Result<()> {
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
