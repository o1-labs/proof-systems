use clap::{arg, Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
pub struct Elf {
    #[arg(
        short = 'e',
        long,
        value_name = "ELF_PATH",
        help = "input ELF file path for riscv"
    )]
    pub path: String,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    #[command(name = "elf")]
    Run(Elf),
}
