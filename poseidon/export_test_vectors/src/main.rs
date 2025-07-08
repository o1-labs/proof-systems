use core::str::FromStr;
use std::{
    env,
    fs::File,
    io::{self, Write},
};
mod vectors;

#[derive(Debug)]
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

#[derive(Debug)]
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

/// Usage:
/// cargo run --all-features \
///           --bin export_test_vectors -- \
///           [b10|hex]
///           [legacy|kimchi]
///           <OUTPUT_FILE>
pub fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        4 => {
            // parse command-line args
            let mode: Mode = args
                .get(1)
                .expect("missing mode")
                .parse()
                .expect("invalid mode");
            let param_type: ParamType = args
                .get(2)
                .expect("missing param type")
                .parse()
                .expect("invalid param type");
            let output_file = args.get(3).expect("missing file");

            // generate vectors
            let vectors = vectors::generate(mode, param_type);

            // save to output file
            let writer: Box<dyn Write> = match output_file.as_str() {
                "-" => Box::new(io::stdout()),
                _ => Box::new(File::create(output_file).expect("could not create file")),
            };
            serde_json::to_writer_pretty(writer, &vectors).expect("could not write to file");
        }
        _ => {
            println!(
                "usage: cargo run -p export_test_vectors -- [{:?}|{:?}] [legacy|kimchi] <OUTPUT_FILE>",
                Mode::Hex,
                Mode::B10,
            );
        }
    }
}
