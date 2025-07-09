use clap::{Parser, ValueEnum};
use core::str::FromStr;
use std::{
    fs::File,
    io::{self, Write},
};
mod vectors;

/// Parse a hex string into a 32-byte seed
fn parse_seed(seed_str: &str) -> Result<[u8; 32], String> {
    if seed_str.len() != 64 {
        return Err(format!(
            "Seed must be exactly 64 hex characters (32 bytes), got {}",
            seed_str.len()
        ));
    }

    let mut seed = [0u8; 32];
    for (i, chunk) in seed_str.as_bytes().chunks(2).enumerate() {
        let hex_str =
            std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8 in seed".to_string())?;
        seed[i] = u8::from_str_radix(hex_str, 16)
            .map_err(|_| format!("Invalid hex character in seed: {}", hex_str))?;
    }

    Ok(seed)
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Mode {
    B10,
    Hex,
}

impl FromStr for Mode {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "b10" => Ok(Mode::B10),
            "hex" => Ok(Mode::Hex),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Es5,
    Json,
}

impl FromStr for OutputFormat {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "es5" => Ok(OutputFormat::Es5),
            "json" => Ok(OutputFormat::Json),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ParamType {
    Legacy,
    Kimchi,
}

impl FromStr for ParamType {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "legacy" => Ok(ParamType::Legacy),
            "kimchi" => Ok(ParamType::Kimchi),
            _ => Err(()),
        }
    }
}

#[derive(Parser)]
#[command(name = "export_test_vectors")]
#[command(about = "Export test vectors for the mina-poseidon crate")]
struct Args {
    /// Number encoding format (base-10 or hexadecimal)
    #[arg(value_enum)]
    mode: Mode,

    /// Parameter type to use
    #[arg(value_enum)]
    param_type: ParamType,

    /// Output file path, use "-" for stdout
    output_file: String,

    /// Output file format
    #[arg(value_enum, default_value = "json", short, long)]
    format: OutputFormat,

    /// Use deterministic output for regression testing (stable version info)
    /// This only affects the version info in ES5 file headers, not the test
    /// vectors themselves. Test vectors always use a fixed seed for
    /// reproducibility.
    /// - deterministic=true: Use crate version (v0.1.0) in ES5 headers
    /// - deterministic=false: Use git commit hash in ES5 headers
    #[arg(long)]
    deterministic: bool,

    /// Custom seed for test vector generation (32 bytes as hex string)
    /// If not provided, uses a default fixed seed for reproducibility.
    /// Example: --seed 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    #[arg(long)]
    seed: Option<String>,
}

pub fn main() {
    let args = Args::parse();

    // Parse seed if provided
    let seed = args.seed.map(|seed_str| {
        parse_seed(&seed_str).unwrap_or_else(|err| {
            eprintln!("Error parsing seed: {}", err);
            std::process::exit(1);
        })
    });

    // generate vectors
    let vectors = vectors::generate(args.mode.clone(), args.param_type.clone(), seed);

    // save to output file
    let mut writer: Box<dyn Write> = match args.output_file.as_str() {
        "-" => Box::new(io::stdout()),
        _ => Box::new(File::create(&args.output_file).expect("could not create file")),
    };

    match args.format {
        OutputFormat::Es5 => {
            vectors::write_es5(&mut writer, &vectors, args.param_type, args.deterministic)
                .expect("could not write to file");
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(writer, &vectors).expect("could not write to file");
        }
    }
}
