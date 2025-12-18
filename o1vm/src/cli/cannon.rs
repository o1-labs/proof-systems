use crate::cannon::*;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
pub struct MipsVmConfigurationArgs {
    #[arg(
        long,
        value_name = "FILE",
        default_value = "state.json",
        help = "initial state file"
    )]
    input: String,

    #[arg(
        long,
        value_name = "FILE",
        default_value = "out.json",
        help = "output state file"
    )]
    output: String,

    #[arg(long, value_name = "FILE", help = "metadata file")]
    meta: Option<String>,

    #[arg(
        long = "proof-at",
        short = 'p',
        long,
        value_name = "FREQ",
        default_value = "never"
    )]
    proof_at: StepFrequency,

    #[arg(
        long = "proof-fmt",
        value_name = "FORMAT",
        default_value = "proof-%d.json"
    )]
    proof_fmt: String,

    #[arg(
        long = "snapshot-fmt",
        value_name = "FORMAT",
        default_value = "state-%d.json"
    )]
    snapshot_fmt: String,

    #[arg(long = "stop-at", value_name = "FREQ", default_value = "never")]
    stop_at: StepFrequency,

    #[arg(long = "info-at", value_name = "FREQ", default_value = "never")]
    info_at: StepFrequency,

    #[arg(long = "pprof.cpu", action = clap::ArgAction::SetTrue)]
    pprof_cpu: bool,

    #[arg(
        long = "snapshot-state-at",
        value_name = "FREQ",
        default_value = "never"
    )]
    snapshot_state_at: StepFrequency,

    #[arg(
        long = "halt-address",
        value_name = "ADDR",
        help = "halt address (in hexadecimal). Jumping to this address will halt the program."
    )]
    halt_address: Option<String>,

    #[arg(name = "host", value_name = "HOST", help = "host program specification <host program> [host program arguments]", num_args = 1.., last = true)]
    host: Vec<String>,
}

impl From<MipsVmConfigurationArgs> for VmConfiguration {
    fn from(cfg: MipsVmConfigurationArgs) -> Self {
        VmConfiguration {
            input_state_file: cfg.input,
            output_state_file: cfg.output,
            metadata_file: cfg.meta,
            proof_at: cfg.proof_at,
            stop_at: cfg.stop_at,
            snapshot_state_at: cfg.snapshot_state_at,
            info_at: cfg.info_at,
            proof_fmt: cfg.proof_fmt,
            snapshot_fmt: cfg.snapshot_fmt,
            pprof_cpu: cfg.pprof_cpu,
            halt_address: cfg.halt_address.map(|s| {
                u32::from_str_radix(s.trim_start_matches("0x"), 16)
                    .expect("Failed to parse halt address as hex")
            }),
            host: if cfg.host.is_empty() {
                None
            } else {
                Some(HostProgram {
                    name: cfg.host[0].to_string(),
                    arguments: cfg.host[1..].to_vec(),
                })
            },
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct RunArgs {
    #[arg(long = "preimage-db-dir", value_name = "PREIMAGE_DB_DIR")]
    pub preimage_db_dir: Option<String>,
    #[arg(long = "srs-filepath", value_name = "SRS_CACHE")]
    pub srs_cache: Option<String>,
    // it's important that vm_cfg is last in order to properly parse the host field
    #[command(flatten)]
    pub vm_cfg: MipsVmConfigurationArgs,
}

#[derive(Parser, Debug, Clone)]
pub struct GenStateJsonArgs {
    #[arg(short = 'i', long, value_name = "FILE", help = "input ELF file")]
    pub input: String,
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        default_value = "state.json",
        help = "output state.json file"
    )]
    pub output: String,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Cannon {
    Run(RunArgs),
    #[command(name = "test-optimism-preimage-read")]
    TestPreimageRead(RunArgs),
    #[command(name = "gen-state-json")]
    GenStateJson(GenStateJsonArgs),
}
