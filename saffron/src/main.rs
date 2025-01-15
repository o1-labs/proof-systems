use anyhow::Result;
use clap::Parser;
use mina_curves::pasta::Fp;
use saffron::cli;
use std::{
    fs::File,
    io::{Read, Write},
};

fn decode_file(args: cli::DecodeFileArgs) -> Result<()> {
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let xs = saffron::serialization::deserialize_vec::<Fp>(&buf);
    let bytes: Vec<u8> = xs
        .into_iter()
        .flat_map(|x| { 
            saffron::serialization::decode(x).as_slice()[1..32].to_vec()
         })
        .collect();
    let mut writer = File::create(args.output)?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn encode_file(args: cli::EncodeFileArgs) -> Result<()> {
    let mut file = File::open(args.input)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let xs = buf
        .chunks(31)
        .map(|chunk| {
            let mut bytes = [0u8; 31];
            bytes[..chunk.len()].copy_from_slice(chunk);
            saffron::serialization::encode(&bytes)
        })
        .collect::<Vec<Fp>>();
    let bytes = saffron::serialization::serialize_vec(&xs);
    let mut writer = File::create(args.output)?;
    writer.write_all(&bytes)?;
    Ok(())
}

pub fn main() -> Result<()> {
    let args = cli::Commands::parse();
    match args {
        cli::Commands::Encode(args) => encode_file(args),
        cli::Commands::Decode(args) => decode_file(args),
    }
}
