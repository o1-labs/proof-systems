use anyhow::Result;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use clap::Parser;
use mina_curves::pasta::{Fp, Vesta};
use poly_commitment::{ipa::SRS, SRS as _};
use saffron::{blob::FieldBlob, cli, commitment, env, utils};
use sha3::{Digest, Sha3_256};
use std::{
    fs::File,
    io::{Read, Write},
};
use tracing::debug;

const DEFAULT_SRS_SIZE: usize = 1 << 16;

fn get_srs(cache: Option<String>) -> (SRS<Vesta>, Radix2EvaluationDomain<Fp>) {
    match cache {
        Some(cache) => {
            let srs = env::get_srs_from_cache(cache);
            let domain_fp = Radix2EvaluationDomain::new(srs.size()).unwrap();
            (srs, domain_fp)
        }
        None => {
            debug!(
                "No SRS cache provided. Creating SRS from scratch with domain size {}",
                DEFAULT_SRS_SIZE
            );
            let domain_size = DEFAULT_SRS_SIZE;
            let srs = SRS::create(domain_size);
            let domain_fp = Radix2EvaluationDomain::new(srs.size()).unwrap();
            srs.get_lagrange_basis(domain_fp);
            debug!("SRS created successfully");
            (srs, domain_fp)
        }
    }
}

fn decode_file(args: cli::DecodeFileArgs) -> Result<()> {
    let (_, domain) = get_srs(args.srs_cache);
    debug!(
        domain_size = domain.size(),
        input_file = args.input,
        "Decoding file"
    );
    let file = File::open(args.input)?;
    let blob: FieldBlob<Vesta> = rmp_serde::decode::from_read(file)?;
    let data = FieldBlob::<Vesta>::decode(domain, blob);
    debug!(output_file = args.output, "Writing decoded blob to file");
    let mut writer = File::create(args.output)?;
    writer.write_all(&data)?;
    Ok(())
}

fn encode_file(args: cli::EncodeFileArgs) -> Result<()> {
    let (srs, domain) = get_srs(args.srs_cache);
    debug!(
        domain_size = domain.size(),
        input_file = args.input,
        "Encoding file"
    );
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let blob = FieldBlob::<Vesta>::encode(&srs, domain, &buf);
    args.assert_commitment
        .into_iter()
        .for_each(|asserted_commitment| {
            let bytes = rmp_serde::to_vec(&blob.commitments).unwrap();
            let hash = Sha3_256::new().chain_update(bytes).finalize();
            let computed_commitment = hex::encode(hash);
            if asserted_commitment != computed_commitment {
                panic!(
                    "commitment hash mismatch: asserted {}, computed {}",
                    asserted_commitment, computed_commitment
                );
            }
        });
    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut writer = File::create(args.output)?;
    rmp_serde::encode::write(&mut writer, &blob)?;
    Ok(())
}

pub fn compute_commitment(args: cli::ComputeCommitmentArgs) -> Result<String> {
    let (srs, domain_fp) = get_srs(args.srs_cache);
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let field_elems = utils::encode_for_domain(&domain_fp, &buf);
    let commitments = commitment::commit_to_field_elems(&srs, domain_fp, field_elems);
    let bytes = rmp_serde::to_vec(&commitments).unwrap();
    let hash = Sha3_256::new().chain_update(bytes).finalize();
    Ok(hex::encode(hash))
}

pub fn main() -> Result<()> {
    env::init_console_subscriber();
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Encode(args) => encode_file(args),
        cli::Commands::Decode(args) => decode_file(args),
        cli::Commands::ComputeCommitment(args) => match compute_commitment(args) {
            Ok(c) => {
                println!("{}", c);
                Ok(())
            }
            Err(e) => {
                eprintln!("{}", e);
                Err(e)
            }
        },
    }
}
