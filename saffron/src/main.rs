use anyhow::Result;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use clap::Parser;
use kimchi::groupmap::GroupMap;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use rand::rngs::OsRng;
use saffron::{
    blob::FieldBlob,
    cli::{self, HexString},
    commitment, encoding, env,
    storage_proof::{self, StorageProof},
    utils::new_sponge,
    Curve, ScalarField, Sponge,
};
use std::{
    fs::File,
    io::{Read, Write},
};
use tracing::{debug, debug_span};

fn get_srs_and_domain(cache: Option<String>) -> (SRS<Curve>, Radix2EvaluationDomain<ScalarField>) {
    let res = match cache {
        Some(cache) => {
            let srs = env::get_srs_from_cache(cache);
            let domain_fp = Radix2EvaluationDomain::new(srs.size()).unwrap();
            (srs, domain_fp)
        }
        None => {
            debug!(
                "No SRS cache provided. Creating SRS from scratch with domain size {}",
                saffron::SRS_SIZE
            );
            let domain_size = saffron::SRS_SIZE;
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
    let (_, domain) = get_srs_and_domain(args.srs_cache);
    debug!(
        domain_size = domain.size(),
        input_file = args.input,
        "Decoding file"
    );
    let file = File::open(args.input)?;
    let blob: FieldBlob = rmp_serde::decode::from_read(file)?;
    let mut data = FieldBlob::into_bytes(blob);
    if let Some(truncate_to_bytes) = args.truncate_to_bytes {
        println!("Truncated to {:?} bytes", truncate_to_bytes);
        data.truncate(truncate_to_bytes as usize);
    }
    debug!(output_file = args.output, "Writing decoded blob to file");
    let mut writer = File::create(args.output)?;
    writer.write_all(&data)?;
    Ok(())
}

fn encode_file(args: cli::EncodeFileArgs) -> Result<()> {
    let (srs, domain) = get_srs_and_domain(args.srs_cache);
    debug!(
        domain_size = domain.size(),
        input_file = args.input,
        "Encoding file"
    );
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let blob = FieldBlob::from_bytes::<_>(&srs, domain, &buf);

    if let Some(asserted) = args.assert_commitment {
        let asserted_commitment: PolyComm<Curve> =
            rmp_serde::from_slice(&asserted.0).expect("failed to decode asserted commitment");

        let challenge_seed_args = args
            .challenge_seed
            .expect("if assert-commitment is requested, challenge-seed must be provided");
        let challenge_seed: ScalarField = encoding::encode(&challenge_seed_args.0);

        let mut sponge = new_sponge();
        sponge.absorb_fr(&[challenge_seed]);
        let (combined_data_commitment, _challenge) =
            commitment::combine_commitments(&mut sponge, blob.commitments.as_slice());

        assert_eq!(
            combined_data_commitment,
            asserted_commitment.chunks[0],
            "commitment mismatch: asserted {}, computed {}",
            asserted,
            HexString(
                rmp_serde::encode::to_vec(&PolyComm {
                    chunks: vec![combined_data_commitment]
                })
                .expect("failed to encode commitment")
            )
        );
    };

    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut writer = File::create(args.output)?;
    rmp_serde::encode::write(&mut writer, &blob)?;

    Ok(())
}

pub fn compute_commitment(args: cli::ComputeCommitmentArgs) -> Result<HexString> {
    let (srs, domain_fp) = get_srs_and_domain(args.srs_cache);

    let buf: Vec<u8> = {
        let mut file = File::open(args.input)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        buf
    };
    let blob = FieldBlob::from_bytes(&srs, domain_fp, buf.as_slice());

    let challenge_seed: ScalarField = encoding::encode(&args.challenge_seed.0);
    let mut sponge = new_sponge();
    sponge.absorb_fr(&[challenge_seed]);
    let (combined_data_commitment, _challenge) =
        commitment::combine_commitments(&mut sponge, blob.commitments.as_slice());

    // Serde can't serialize group elements on its own (???)
    let commitments_as_polycomm: Vec<PolyComm<Curve>> = blob
        .commitments
        .into_iter()
        .map(|c| PolyComm { chunks: vec![c] })
        .collect();

    let combined_data_commitment_as_polycomm: PolyComm<Curve> = PolyComm {
        chunks: vec![combined_data_commitment],
    };

    // this seems completely unnecessary
    {
        let mut writer = File::create(args.output)?;

        rmp_serde::encode::write(
            &mut writer,
            &(
                commitments_as_polycomm,
                combined_data_commitment_as_polycomm.clone(),
            ),
        )?;
    }

    let combined_data_commitment_hex =
        rmp_serde::encode::to_vec(&combined_data_commitment_as_polycomm)?;

    Ok(HexString(combined_data_commitment_hex))
}

pub fn storage_proof(args: cli::StorageProofArgs) -> Result<HexString> {
    let file = File::open(args.input)?;
    let blob: FieldBlob = rmp_serde::decode::from_read(file)?;
    let challenge_seed: ScalarField = encoding::encode(&args.challenge_seed.0);
    let proof = {
        let (srs, _) = get_srs_and_domain(args.srs_cache);
        let group_map = <Curve as CommitmentCurve>::Map::setup();
        let mut rng = OsRng;

        let mut sponge = new_sponge();
        sponge.absorb_fr(&[challenge_seed]);
        let (_combined_data_commitment, challenge) =
            commitment::combine_commitments(&mut sponge, blob.commitments.as_slice());

        storage_proof::prove(&srs, &group_map, blob, challenge, &mut rng)
    };
    let res = rmp_serde::to_vec(&proof)?;
    Ok(HexString(res))
}

pub fn verify_storage_proof(args: cli::VerifyStorageProofArgs) -> Result<()> {
    let (srs, _) = get_srs_and_domain(args.srs_cache);
    let group_map = <Curve as CommitmentCurve>::Map::setup();

    let combined_data_commitment: PolyComm<Curve> = rmp_serde::from_slice(&args.commitment.0)?;
    let combined_data_commitment = combined_data_commitment.chunks[0];

    let proof: StorageProof = rmp_serde::from_slice(&args.proof.0)?;
    let mut rng = OsRng;
    let res = storage_proof::verify_wrt_combined_data_commitment(
        &srs,
        &group_map,
        combined_data_commitment,
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
            let commitment = compute_commitment(args)?;
            println!("combined_data_commitment: {}", commitment);
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
