use std::{collections::HashMap, env, path::PathBuf};

use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};

fn main() {
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(dbg!(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()));
    let mut builder = GuestOptionsBuilder::default();
    if env::var("RISC0_USE_DOCKER").is_ok() {
        let docker_options = DockerOptionsBuilder::default()
            .root_dir(manifest_dir.join(".."))
            .build()
            .unwrap();
        builder.use_docker(docker_options);
    }
    let guest_options = builder.build().unwrap();

    let _guests = embed_methods_with_options(HashMap::from([("risc0-test-guest", guest_options)]));
}
