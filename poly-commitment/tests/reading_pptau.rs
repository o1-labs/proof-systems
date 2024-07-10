//! Parsing ptau file from snarkjs
//! See
//! [perpetualpoweroftau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau).
//! It is for the bn254 curve.
//! The format is `ptau`, described in snarkjs, see
//! https://github.com/iden3/snarkjs/blob/e094f553c0cded760432f0ad9068a143dbed107f/src/powersoftau_utils.js

use std::{fs::File, path::PathBuf};

use std::io::Read;

#[test]
fn test_reading_pptau() {
    let test_vector_file = "ppot_0080_05.ptau";
    // read test vectors from given file
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../srs/");
    path.push(test_vector_file);
    {
        let mut file = File::open(&path).expect("couldn't open test vector file");
        let mut buffer = Vec::new();
        // read the whole file
        file.read_to_end(&mut buffer).unwrap();
        println!("Number of bytes: {}", buffer.len())
    }
    {
        let mut file = File::open(&path).expect("couldn't open test vector file");
        let mut buffer: [u8; 32] = [0; 32];
        file.read_exact(&mut buffer).expect("couldn't read test vector file");
        println!("{:?}", buffer);
    }
}
