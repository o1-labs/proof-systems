use anyhow::Result;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use mina_curves::pasta::Fp;
use saffron::{cli, serialization::FieldBlob};
use std::{
    fs::File,
    io::{Read, Write},
};
use time::macros::format_description;
use tracing::debug;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    EnvFilter,
};

const SRS_SIZE: usize = 1 << 16;

fn decode_file(args: cli::DecodeFileArgs) -> Result<()> {
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
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
    let domain = Radix2EvaluationDomain::new(SRS_SIZE).unwrap();
    debug!(
        domain_size = domain.size(),
        input_file = args.input,
        "Encoding file"
    );
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let blob = FieldBlob::<Fp>::encode(domain, &buf);
    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut bytes_to_write = Vec::with_capacity(buf.len());
    blob.serialize_compressed(&mut bytes_to_write)?;
    debug!(output_file = args.output, "Writing encoded blob to file",);
    let mut writer = File::create(args.output)?;
    writer.write_all(&bytes_to_write)?;
    Ok(())
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
    }
}
