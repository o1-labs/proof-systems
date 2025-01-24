use anyhow::Result;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use kimchi::precomputed_srs::TestSRS;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{constants::PlonkSpongeConstantsKimchi, sponge::DefaultFqSponge, FqSponge};
use poly_commitment::{ipa::SRS, PolyComm, SRS as _};
use saffron::{blob::FieldBlob, cli, commitment, utils};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use time::macros::format_description;
use tracing::debug;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    EnvFilter,
};

const DEFAULT_SRS_SIZE: usize = 1 << 16;

fn get_srs(cache: Option<String>) -> (SRS<Vesta>, Radix2EvaluationDomain<Fp>) {
    match cache {
        Some(cache) => {
            debug!("Loading SRS from cache {}", cache);
            let file_path = Path::new(&cache);
            let file = File::open(file_path).expect("Error opening SRS cache file");
            let srs: SRS<Vesta> = {
                // By convention, proof systems serializes a TestSRS with filename 'test_<CURVE_NAME>.srs'.
                // The benefit of using this is you don't waste time verifying the SRS.
                if file_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("test_")
                {
                    let test_srs: TestSRS<Vesta> = rmp_serde::from_read(&file).unwrap();
                    From::from(test_srs)
                } else {
                    rmp_serde::from_read(&file).unwrap()
                }
            };
            debug!("SRS loaded successfully from cache");
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
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let blob: FieldBlob<Fp> = FieldBlob::<Fp>::deserialize_compressed(&buf[..])?;
    let data = FieldBlob::<Fp>::decode(domain, blob);
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
    let blob = FieldBlob::<Fp>::encode(domain, &buf);
    args.assert_commitment
        .into_iter()
        .for_each(|asserted_commitment| {
            let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
                mina_poseidon::pasta::fq_kimchi::static_params(),
            );
            let commitments = commitment::commit_to_blob(&srs, &blob);
            let c: PolyComm<ark_ec::short_weierstrass::Affine<VestaParameters>> =
                commitment::fold_commitments(&mut fq_sponge, &commitments);
            let bytes = serde_json::to_vec(&c).unwrap();
            let computed_commitment = hex::encode(bytes);
            if asserted_commitment != computed_commitment {
                panic!(
                    "commitment mismatch: asserted {}, computed {}",
                    asserted_commitment, computed_commitment
                );
            }
        });
    let mut bytes_to_write = Vec::with_capacity(buf.len());
    blob.serialize_compressed(&mut bytes_to_write)?;
    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut writer = File::create(args.output)?;
    writer.write_all(&bytes_to_write)?;
    Ok(())
}

pub fn compute_commitment(args: cli::ComputeCommitmentArgs) -> Result<String> {
    let (srs, domain_fp) = get_srs(args.srs_cache);
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let field_elems = utils::encode_for_domain(&domain_fp, &buf);
    let mut fq_sponge = DefaultFqSponge::<VestaParameters, PlonkSpongeConstantsKimchi>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );
    let commitments = commitment::commit_to_field_elems(&srs, domain_fp, field_elems);
    let c: PolyComm<ark_ec::short_weierstrass::Affine<VestaParameters>> =
        commitment::fold_commitments(&mut fq_sponge, &commitments);
    let bytes = serde_json::to_vec(&c).unwrap();
    Ok(hex::encode(bytes))
}

pub fn init_subscriber() {
    let timer = UtcTime::new(format_description!(
        "[year]-[month]-[day]T[hour repr:24]:[minute]:[second].[subsecond digits:3]Z"
    ));
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::CLOSE)
        .with_timer(timer)
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(false)
        .with_file(false)
        .with_level(true)
        .with_ansi(true)
        .with_writer(std::io::stdout)
        .init();
}

pub fn main() -> Result<()> {
    init_subscriber();
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
