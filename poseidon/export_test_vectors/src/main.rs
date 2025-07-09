use clap::{Parser, ValueEnum};
use core::str::FromStr;
use std::{
    fs::File,
    io::{self, Write},
};
mod vectors;

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
}

pub fn main() {
    let args = Args::parse();

    // generate vectors
    let vectors = vectors::generate(args.mode.clone(), args.param_type.clone());

    // save to output file
    let mut writer: Box<dyn Write> = match args.output_file.as_str() {
        "-" => Box::new(io::stdout()),
        _ => Box::new(File::create(&args.output_file).expect("could not create file")),
    };

    match args.format {
        OutputFormat::Es5 => {
            vectors::write_es5(&mut writer, &vectors, args.param_type)
                .expect("could not write to file");
        }
        OutputFormat::Json => {
            serde_json::to_writer_pretty(writer, &vectors).expect("could not write to file");
        }
    }
}
