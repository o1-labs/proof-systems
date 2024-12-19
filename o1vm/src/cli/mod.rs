use clap::Parser;

pub mod cannon;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "o1vm",
    version = "0.1",
    about = "o1vm - a generic purpose zero-knowledge virtual machine"
)]
pub enum Commands {
    #[command(subcommand)]
    Cannon(cannon::Cannon),
}
