use anyhow::Result;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use clap::Parser;
use kimchi::groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge};
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
use rand::rngs::OsRng;
use saffron::{
    blob::FieldBlob,
    cli::{self, HexString},
    commitment, env, proof, utils,
};
use sha3::{Digest, Sha3_256};
use std::{
    fs::File,
    io::{Read, Write},
};
use tracing::{debug, debug_span};

const DEFAULT_SRS_SIZE: usize = 1 << 16;

fn get_srs(cache: Option<String>) -> (SRS<Vesta>, Radix2EvaluationDomain<Fp>) {
    let res = match cache {
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
            debug!("SRS created successfully");
            (srs, domain_fp)
        }
    };

    debug_span!("get_lagrange_basis", basis_size = res.0.size()).in_scope(|| {
        res.0.get_lagrange_basis(res.1);
    });

    res
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
            let hash = Sha3_256::new().chain_update(bytes).finalize().to_vec();
            if asserted_commitment.0 != hash {
                panic!(
                    "commitment hash mismatch: asserted {}, computed {}",
                    asserted_commitment,
                    HexString(hash)
                );
            }
        });
    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut writer = File::create(args.output)?;
    rmp_serde::encode::write(&mut writer, &blob)?;
    Ok(())
}

pub fn compute_commitment(args: cli::ComputeCommitmentArgs) -> Result<HexString> {
    let (srs, domain_fp) = get_srs(args.srs_cache);
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let field_elems = utils::encode_for_domain(&domain_fp, &buf);
    let commitments = commitment::commit_to_field_elems(&srs, domain_fp, field_elems);
    let bytes = rmp_serde::to_vec(&commitments).unwrap();
    let hash = Sha3_256::new().chain_update(bytes).finalize().to_vec();
    Ok(HexString(hash))
}

pub fn storage_proof(args: cli::StorageProofArgs) -> Result<HexString> {
    let file = File::open(args.input)?;
    let blob: FieldBlob<Vesta> = rmp_serde::decode::from_read(file)?;
    let proof =
        {
            let (srs, _) = get_srs(args.srs_cache);
            let group_map = <Vesta as CommitmentCurve>::Map::setup();
            let mut rng = OsRng;
            let evaluation_point = utils::encode(&args.challenge.0);
            proof::storage_proof::<
                Vesta,
                DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
            >(&srs, &group_map, blob, evaluation_point, &mut rng)
        };
    let bytes = rmp_serde::to_vec(&proof).unwrap();
    Ok(HexString(bytes))
}

pub fn main() -> Result<()> {
    env::init_console_subscriber();
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Encode(args) => encode_file(args),
        cli::Commands::Decode(args) => decode_file(args),
        cli::Commands::ComputeCommitment(args) => {
            let commitment = compute_commitment(args)?;
            println!("{}", commitment);
            Ok(())
        }
        cli::Commands::StorageProof(args) => {
            let proof = storage_proof(args)?;
            println!("{}", proof);
            Ok(())
        }
    }
}
