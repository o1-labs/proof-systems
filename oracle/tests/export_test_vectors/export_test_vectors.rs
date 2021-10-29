use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::str::FromStr;

mod vectors;

#[derive(Debug)]
pub enum Mode {
    Hex,
    B10,
}

impl FromStr for Mode {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "B10" => Ok(Mode::B10),
            _ => Ok(Mode::Hex),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        3 => {
            // parse command-line args
            let mode: Mode = args
                .get(1)
                .expect("missing mode")
                .parse()
                .expect("invalid mode");
            let output_file = args.get(2).expect("missing file");

            // generate vectors
            let vectors = vectors::generate(mode);

            // save to output file
            let writer: Box<dyn Write> = match output_file.as_str() {
                "-" => Box::new(io::stdout()),
                _ => Box::new(File::create(output_file).expect("could not create file")),
            };
            serde_json::to_writer_pretty(writer, &vectors).expect("could not write to file");
        }
        _ => {
            println!(
                "usage: cargo run --bin export_test_vectors --no-default-features --features [3w|5w|3] -- [{:?}|{:?}] <OUTPUT_FILE>",
                Mode::Hex,
                Mode::B10
            );
            
        }
    }
}
