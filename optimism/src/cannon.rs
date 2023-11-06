// Data structure and stuff for compatibility with Cannon

use base64::{engine::general_purpose, Engine as _};

use libflate::zlib::Decoder;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::io::Read;

pub const PAGE_ADDRESS_SIZE: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_ADDRESS_SIZE;
pub const PAGE_ADDRESS_MASK: usize = PAGE_SIZE - 1;

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

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub start: u32,
    pub size: usize,
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub struct Meta {
    symbols: Vec<Symbol>,
}

impl Meta {
    pub fn find_address_symbol(&self, address: u32) -> Option<String> {
        for e in self.symbols.iter() {
            if address >= e.start && address <= (e.start + e.size as u32) {
                return Some(e.name.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::fs::File;
    use std::io::{BufReader, Write};

    #[test]
    fn sp_parser() {
        use StepFrequency::*;
        assert_eq!(step_frequency_parser("never"), Ok(Never));
        assert_eq!(step_frequency_parser("always"), Ok(Always));
        assert_eq!(step_frequency_parser("=123"), Ok(Exactly(123)));
        assert_eq!(step_frequency_parser("%123"), Ok(Every(123)));
        assert!(step_frequency_parser("@123").is_err());
    }

    // This sample is a subset taken from a Cannon-generated "meta.json" file
    const META_SAMPLE: &str = r#"{
  "symbols": [
    {
      "name": "go.go",
      "start": 0,
      "size": 0
    },
    {
      "name": "internal/cpu.processOptions",
      "start": 69632,
      "size": 1872
    },
    {
      "name": "runtime.text",
      "start": 69632,
      "size": 0
    }]}"#;

    #[test]
    fn test_meta_deserialize_from_file() {
        let path = "meta_test.json";
        let mut output =
            File::create(path).unwrap_or_else(|_| panic!("Could not create file {path}"));
        write!(output, "{}", META_SAMPLE)
            .unwrap_or_else(|_| panic!("Could not write to file {path}"));

        let input = File::open(path).unwrap_or_else(|_| panic!("Could not open file {path}"));
        let buffered = BufReader::new(input);
        let read: Meta = serde_json::from_reader(buffered)
            .unwrap_or_else(|_| panic!("Failed to deserialize metadata from file {path}"));

        let expected = Meta {
            symbols: vec![
                Symbol {
                    name: "go.go".to_string(),
                    start: 0_u32,
                    size: 0,
                },
                Symbol {
                    name: "internal/cpu.processOptions".to_string(),
                    start: 69632,
                    size: 1872,
                },
                Symbol {
                    name: "runtime.text".to_string(),
                    start: 69632,
                    size: 0,
                },
            ],
        };
        assert_eq!(read, expected);
    }
}
