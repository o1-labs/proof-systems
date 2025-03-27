use anyhow::Result;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use clap::Parser;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use rand::rngs::OsRng;
use saffron::{
    blob::FieldBlob,
    cli::{self, HexString},
    commitment::{self, commit_to_field_elems},
    env,
    storage_proof::{self, StorageProof},
    utils, Curve, CurveFqSponge, ScalarField,
};
use std::{
    fs::File,
    io::{Read, Write},
};
use tracing::{debug, debug_span};

pub const DEFAULT_SRS_SIZE: usize = 1 << 16;

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
    let blob: FieldBlob = rmp_serde::decode::from_read(file)?;
    let data = FieldBlob::into_bytes(domain, blob);
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
    let blob = FieldBlob::from_bytes::<_>(&srs, domain, &buf);

    let commitments_polycomm: Vec<PolyComm<_>> = blob
        .commitments
        .iter()
        .map(|com| PolyComm {
            chunks: vec![com.clone()],
        })
        .collect();
    let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    let (randomized_data_commitment, challenge) =
        commitment::combine_commitments(&mut sponge, commitments_polycomm.as_slice());

    if let Some(asserted) = args.assert_commitment {
        let asserted_commitment =
            rmp_serde::from_slice(&asserted.0).expect("failed to decode asserted commitment");

        assert_eq!(
            randomized_data_commitment,
            asserted_commitment,
            "commitment mismatch: asserted {}, computed {}",
            asserted,
            HexString(
                rmp_serde::encode::to_vec(&randomized_data_commitment)
                    .expect("failed to encode commitment")
            )
        );
    };
    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut writer = File::create(args.output)?;
    rmp_serde::encode::write(&mut writer, &blob)?;
    Ok(())
}

pub fn compute_commitment(args: cli::ComputeCommitmentArgs) -> Result<(HexString, HexString)> {
    let (srs, domain_fp) = get_srs(args.srs_cache);
    let buf: Vec<u8> = {
        let mut file = File::open(args.input)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        buf
    };
    let blob = FieldBlob::from_bytes(&srs, domain_fp, buf.as_slice());
    let commitments_polycomm: Vec<PolyComm<_>> = blob
        .commitments
        .iter()
        .map(|com| PolyComm {
            chunks: vec![com.clone()],
        })
        .collect();
    let mut sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    let (randomized_data_commitment, challenge) =
        commitment::combine_commitments(&mut sponge, commitments_polycomm.as_slice());

    {
        let mut writer = File::create(args.output)?;
        rmp_serde::encode::write(
            &mut writer,
            &(commitments_polycomm, randomized_data_commitment.clone()),
        )?;
    }

    let randomized_data_commitment_hex = rmp_serde::encode::to_vec(&randomized_data_commitment)?;
    let challenge_hex: Vec<u8> = utils::decode_into_vec(challenge);
    Ok((
        HexString(randomized_data_commitment_hex),
        HexString(challenge_hex),
    ))
}

pub fn storage_proof(args: cli::StorageProofArgs) -> Result<HexString> {
    let file = File::open(args.input)?;
    let blob: FieldBlob = rmp_serde::decode::from_read(file)?;
    let proof = {
        let (srs, _) = get_srs(args.srs_cache);
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        let mut rng = OsRng;
        let challenge = utils::encode(&args.challenge.0);
        storage_proof::prove(&srs, &group_map, blob, challenge, &mut rng)
    };
    let res = rmp_serde::to_vec(&proof)?;
    Ok(HexString(res))
}

pub fn verify_storage_proof(args: cli::VerifyStorageProofArgs) -> Result<()> {
    let (srs, _) = get_srs(args.srs_cache);
    let group_map = <Curve as CommitmentCurve>::Map::setup();
    let randomized_data_commitment: PolyComm<Curve> = rmp_serde::from_slice(&args.commitment.0)?;
    let randomized_data_commitment = randomized_data_commitment.chunks[0];

    let proof: StorageProof = rmp_serde::from_slice(&args.proof.0)?;
    let mut rng = OsRng;
    let res = storage_proof::verify_fast(
        &srs,
        &group_map,
        randomized_data_commitment,
        &proof,
        &mut rng,
    );
    assert!(res, "Proof must verify");
    Ok(())
}

pub fn main() -> Result<()> {
    env::init_console_subscriber();
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Encode(args) => encode_file(args),
        cli::Commands::Decode(args) => decode_file(args),
        cli::Commands::ComputeCommitment(args) => {
            let (commitment, challenge) = compute_commitment(args)?;
            println!("randomized_data_commitment: {}", commitment);
            println!("challenge: {}", challenge);
            Ok(())
        }
        cli::Commands::StorageProof(args) => {
            let proof = storage_proof(args)?;
            println!("proof: {}", proof);
            Ok(())
        }
        cli::Commands::VerifyStorageProof(args) => verify_storage_proof(args),
    }
}
