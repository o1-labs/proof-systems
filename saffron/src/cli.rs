use clap::{arg, Parser};

#[derive(Parser)]
pub struct EncodeFileArgs {
    #[arg(long, short = 'i', value_name = "FILE", help = "input file")]
    pub input: String,

    #[arg(
        long,
        short = 'o',
        value_name = "FILE",
        help = "output file (encoded as field elements)"
    )]
    pub output: String,

    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,

    #[arg(long = "assert-commitment", value_name = "COMMITMENT")]
    pub assert_commitment: Option<String>,
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
}

#[derive(Parser)]
pub struct ComputeCommitmentArgs {
    #[arg(long, short = 'i', value_name = "FILE", help = "input file")]
    pub input: String,

    #[arg(long = "srs-filepath", value_name = "SRS_FILEPATH")]
    pub srs_cache: Option<String>,
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
}
