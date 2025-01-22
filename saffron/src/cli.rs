use clap::{arg, Parser};

#[derive(Parser, Debug, Clone)]
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
}

#[derive(Parser, Debug, Clone)]
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
}

#[derive(Parser, Debug, Clone)]
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
}
