#[cfg(feature = "test_vectors")]
mod vectors;
#[cfg(feature = "test_vectors")]
use inner::*;

/// "Usage: cargo run --all-features --bin export_test_vectors -- [hex|b10] [legacy|kimchi] <OUTPUT_FILE>",
fn main() {
    #[cfg(feature = "test_vectors")]
    inner::main();
    #[cfg(not(feature = "test_vectors"))]
    println!("Error: this tool should be compiled with feature 'test_vectors'");
}

#[cfg(feature = "test_vectors")]
mod inner {
    use super::vectors;
    use std::env;
    use std::fs::File;
    use std::io::{self, Write};
    use std::str::FromStr;

    #[derive(Debug)]
    pub enum Mode {
        Hex,
        B10,
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

    pub(crate) fn main() {
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
                "usage: cargo run --all-features --bin export_test_vectors -- [{:?}|{:?}] [legacy|kimchi] <OUTPUT_FILE>",
                Mode::Hex,
                Mode::B10,
            );
            }
        }
    }
}
