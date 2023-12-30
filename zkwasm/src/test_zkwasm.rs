use clap::Arg;
use log::{debug, error};
use std::{
    io::{self},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};
use zkwasm::{
    cannon::PreimageKey,
    cannon_cli::{main_cli, read_configuration},
    preimage_oracle::PreImageOracle,
};

fn main() -> ExitCode {
    env_logger::init();

    ExitCode::SUCCESS
}
