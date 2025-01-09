use clap::Parser;

pub mod cannon;
pub mod riscv;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "o1vm",
    version = "0.1",
    about = "o1vm - a generic purpose zero-knowledge virtual machine"
)]
pub enum Commands {
    #[command(subcommand)]
    Cannon(Box<cannon::Cannon>),
    #[command(subcommand)]
    RiscV(riscv::Command),
}
