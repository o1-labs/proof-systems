use std::env;
use std::fs::File;

mod vectors;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1) {
        None => {
            println!(
                "usage: cargo run --bin export_test_vectors --no-default-features --features [three_wire|five_wire] -- <OUTPUT_FILE>"
            );
            return;
        }
        Some(output_file) => {
            // generate vectors
            let vectors = vectors::generate();

            // save to output file
            let output_file = &File::create(output_file).expect("could not create file");
            serde_json::to_writer_pretty(output_file, &vectors).expect("could not write to file");
        }
    }
}
