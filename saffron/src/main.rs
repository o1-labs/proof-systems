use anyhow::Result;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use mina_curves::pasta::Fp;
use saffron::{cli, serialization::FieldBlob};
use std::{
    fs::File,
    io::{Read, Write},
};

fn decode_file(args: cli::DecodeFileArgs) -> Result<()> {
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let blob: FieldBlob<Fp> = FieldBlob::<Fp>::deserialize_compressed(&buf[..])?;
    let data = FieldBlob::<Fp>::decode(blob);
    let mut writer = File::create(args.output)?;
    writer.write_all(&data)?;
    Ok(())
}

fn encode_file(args: cli::EncodeFileArgs) -> Result<()> {
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let blob = FieldBlob::<Fp>::encode(&buf);
    let mut bytes_to_write = Vec::with_capacity(buf.len());
    blob.serialize_compressed(&mut bytes_to_write)?;
    let mut writer = File::create(args.output)?;
    writer.write_all(&bytes_to_write)?;
    Ok(())
}

pub fn main() -> Result<()> {
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Encode(args) => encode_file(args),
        cli::Commands::Decode(args) => decode_file(args),
    }
}
