// Data structure and stuff for compatibility with Cannon

use base64::{engine::general_purpose, Engine as _};
use libflate::zlib::Decoder;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::io::Read;

pub const PAGE_SIZE: usize = 4096;

#[derive(Serialize, Deserialize, Debug)]
pub struct Page {
    pub index: u32,
    #[serde(deserialize_with = "from_base64")]
    pub data: Vec<u8>,
}

fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let b64_decoded = general_purpose::STANDARD.decode(s).unwrap();
    let mut decoder = Decoder::new(&b64_decoded[..]).unwrap();
    let mut data = Vec::new();
    decoder.read_to_end(&mut data).unwrap();
    assert_eq!(data.len(), PAGE_SIZE);
    Ok(data)
}

// The renaming below keeps compatibility with OP Cannon's state format
#[derive(Serialize, Deserialize, Debug)]
pub struct State {
    pub memory: Vec<Page>,
    #[serde(rename = "preimageKey")]
    pub preimage_key: String,
    #[serde(rename = "preimageOffset")]
    pub preimage_offset: u32,
    pub pc: u32,
    #[serde(rename = "nextPC")]
    next_pc: u32, //
    pub lo: u32,
    pub hi: u32,
    pub heap: u32,
    exit: u8,
    pub exited: bool,
    pub step: u64,
    pub registers: [u32; 32],
    pub last_hint: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StepFrequency {
    Never,
    Always,
    Exactly(u64),
    Every(u64),
}

// Simple parser for Cannon's "frequency format"
// A frequency input is either
// - never/always
// - =<n> (only at step n)
// - %<n> (every steps multiple of n)
pub fn step_frequency_parser(s: &str) -> std::result::Result<StepFrequency, String> {
    use StepFrequency::*;

    let mod_re = Regex::new(r"%([0-9]+)").unwrap();
    let eq_re = Regex::new(r"=([0-9]+)").unwrap();

    match s {
        "never" => Ok(Never),
        "always" => Ok(Always),
        s => {
            if let Some(m) = mod_re.captures(s) {
                Ok(Every(m[1].parse::<u64>().unwrap()))
            } else if let Some(m) = eq_re.captures(s) {
                Ok(Exactly(m[1].parse::<u64>().unwrap()))
            } else {
                Err(format!("Unknown frequency format {}", s))
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn sp_parser() {
        use StepFrequency::*;
        assert_eq!(step_frequency_parser("never"), Ok(Never));
        assert_eq!(step_frequency_parser("always"), Ok(Always));
        assert_eq!(step_frequency_parser("=123"), Ok(Exactly(123)));
        assert_eq!(step_frequency_parser("%123"), Ok(Every(123)));
        assert!(step_frequency_parser("@123").is_err());
    }
}

impl ToString for State {
    // A very debatable and incomplete, but serviceable, `to_string` implementation.
    fn to_string(&self) -> String {
        format!(
            "memory_size (length): {}\nfirst page size: {}\npreimage key: {}\npreimage offset:{}\npc: {}\nlo: {}\nhi: {}\nregisters:{:#?} ",
            self.memory.len(),
            self.memory[0].data.len(),
            self.preimage_key,
            self.preimage_offset,
            self.pc,
            self.lo,
            self.hi,
            self.registers
        )
    }
}

#[derive(Debug, Clone)]
pub struct HostProgram {
    pub name: String,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VmConfiguration {
    pub input_state_file: String,
    pub output_state_file: String,
    pub metadata_file: String,
    pub proof_at: StepFrequency,
    pub stop_at: StepFrequency,
    pub info_at: StepFrequency,
    pub proof_fmt: String,
    pub snapshot_fmt: String,
    pub pprof_cpu: bool,
    pub host: Option<HostProgram>,
}

#[derive(Debug, Clone)]
pub struct Start {
    pub time: std::time::Instant,
    pub step: usize,
}

impl Start {
    pub fn create(step: usize) -> Start {
        Start {
            time: std::time::Instant::now(),
            step,
        }
    }
}
