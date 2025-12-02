#![allow(clippy::zombie_processes)]

use crate::{
    cannon::{PreimageKey, VmConfiguration},
    cli,
    preimage_oracle::{PreImageOracle, PreImageOracleT},
};
use log::{debug, error};
use std::{
    io::{self},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

pub fn main(args: cli::cannon::RunArgs) -> ExitCode {
    use rand::Rng;

    let configuration: VmConfiguration = args.vm_cfg.into();
    let preimage_db_dir = args.preimage_db_dir;

    if let Some(preimage_key_dir) = preimage_db_dir {
        let host_program = configuration.host.expect("No host program specified");
        let mut po = PreImageOracle::create(host_program);
        let _child = po.start();
        debug!("Let server start");
        std::thread::sleep(std::time::Duration::from_secs(5));

        debug!("Reading from {}", preimage_key_dir);
        // Get all files under the preimage db dir
        let paths = std::fs::read_dir(preimage_key_dir)
            .unwrap()
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, io::Error>>()
            .unwrap();

        // Just take 10 elements at random to test
        let how_many = 10_usize;
        let max = paths.len();
        let mut rng = rand::thread_rng();

        let mut selected: Vec<PathBuf> = vec![PathBuf::new(); how_many];
        for pb in selected.iter_mut() {
            let idx = rng.gen_range(0..max);
            *pb = paths[idx].to_path_buf();
        }

        for (idx, path) in selected.into_iter().enumerate() {
            let preimage_key = Path::new(&path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .split('.')
                .collect::<Vec<_>>()[0];

            let hash = PreimageKey::from_str(preimage_key).unwrap();
            let mut key = hash.0;
            key[0] = 2; // Keccak

            debug!(
                "Generating OP Keccak key for {} at index {}",
                preimage_key, idx
            );

            let expected = std::fs::read_to_string(path).unwrap();

            debug!("Asking for preimage");
            let preimage = po.get_preimage(key);
            let got = hex::encode(preimage.get()).to_string();

            assert_eq!(expected, got);
        }
        ExitCode::SUCCESS
    } else {
        error!("Unset command-line argument --preimage-db-dir. Cannot run test. Please set parameter and rerun.");
        ExitCode::FAILURE
    }
}
