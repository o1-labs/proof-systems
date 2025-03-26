use clap::{arg, Parser};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone)]
pub struct HexString(pub Vec<u8>);

impl FromStr for HexString {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        Ok(HexString(hex::decode(stripped)?))
    }
}

impl Display for HexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

#[derive(Parser)]
pub struct EncodeFileArgs {
    #[arg(long, short = 'i', value_name = "FILE", help = "input file")]
    pub input: String,

    #[arg(
        long,
        short = 'o',
        value_name = "FILE",
        help = "output file (blob, encoded as field elements)"
    )]
    pub output: String,

    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,

    #[arg(
        long = "assert-commitment",
        value_name = "COMMITMENT",
        help = "hash of commitments (hex encoded)"
    )]
    pub assert_commitment: Option<HexString>,

    #[arg(
        long = "challenge-seed",
        value_name = "CHALLENGE_SEED",
        help = "challenge seed (hex encoded, used only if assert-commitment is provided)"
    )]
    pub challenge_seed: Option<HexString>,
}

#[derive(Parser)]
pub struct DecodeFileArgs {
    #[arg(
        long,
        short = 'i',
        value_name = "FILE",
        help = "input file (encoded as field elements)"
    )]
    pub input: String,

    #[arg(long, short = 'o', value_name = "FILE", help = "output file")]
    pub output: String,

    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,

    #[arg(long = "truncate-to-bytes", value_name = "TRUNCATE_TO_BYTES")]
    pub truncate_to_bytes: Option<u64>,
}

#[derive(Parser)]
pub struct ComputeCommitmentArgs {
    #[arg(long, short = 'i', value_name = "FILE", help = "input file")]
    pub input: String,

    #[arg(long, short = 'o', value_name = "FILE", help = "output file")]
    pub output: String,

    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,

    #[arg(
        long = "challenge-seed",
        value_name = "CHALLENGE_SEED",
        help = "challenge seed (hex encoded)"
    )]
    pub challenge_seed: HexString,
}

#[derive(Parser)]
pub struct StorageProofArgs {
    #[arg(
        long,
        short = 'i',
        value_name = "FILE",
        help = "input file (blob, encoded as field elements)"
    )]
    pub input: String,

    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,

    #[arg(
        long = "challenge-seed",
        value_name = "CHALLENGE_SEED",
        help = "challenge seed (hex encoded)"
    )]
    pub challenge_seed: HexString,
}

#[derive(Parser)]
pub struct VerifyStorageProofArgs {
    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,

    #[arg(
        long,
        short = 'c',
        value_name = "COMMITMENT",
        help = "commitment (hex encoded)"
    )]
    pub commitment: HexString,

    #[arg(
        long = "challenge-seed",
        value_name = "CHALLENGE_SEED",
        help = "challenge seed (hex encoded)"
    )]
    pub challenge_seed: HexString,

    #[arg(long, short = 'p', value_name = "PROOF", help = "proof (hex encoded)")]
    pub proof: HexString,
}

#[derive(Parser)]
#[command(
    name = "saffron",
    version = "0.1",
    about = "saffron - a mutable state layer"
)]
pub enum Commands {
    #[command(name = "encode")]
    Encode(EncodeFileArgs),
    #[command(name = "decode")]
    Decode(DecodeFileArgs),
    #[command(name = "compute-commitment")]
    ComputeCommitment(ComputeCommitmentArgs),
    #[command(name = "storage-proof")]
    StorageProof(StorageProofArgs),
    #[command(name = "verify-storage-proof")]
    VerifyStorageProof(VerifyStorageProofArgs),
}
