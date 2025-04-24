use clap::Parser;

#[derive(Parser)]
pub struct ExecuteArgs {
    #[arg(
        long = "zkapp",
        value_name = "ZKAPP",
        help = "the selected zkapp to execute"
    )]
    pub zkapp: String,

    #[arg(long, short = 'n', value_name = "N", help = "Number of iterations")]
    pub n: u64,

    #[arg(
        long = "srs-size",
        value_name = "SRS_SIZE",
        help = "The SRS size, given in log2"
    )]
    pub srs_size: usize,
}

#[derive(Parser)]
#[command(
    name = "arrabbiata",
    version = "0.1",
    about = "Arrabbiata - a generic recursive SNARK based on folding schemes"
)]
pub enum Commands {
    #[command(name = "execute")]
    Execute(ExecuteArgs),
}
