// Data structure and stuff for compatibility with Cannon

use base64::{engine::general_purpose, Engine as _};

use core::{
    fmt,
    fmt::{Display, Formatter},
};
use libflate::zlib::{Decoder, Encoder};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Read, Write};

pub const PAGE_ADDRESS_SIZE: u32 = 12;
pub const PAGE_SIZE: u32 = 1 << PAGE_ADDRESS_SIZE;
pub const PAGE_ADDRESS_MASK: u32 = PAGE_SIZE - 1;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Page {
    pub index: u32,
    #[serde(deserialize_with = "from_base64", serialize_with = "to_base64")]
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
    assert_eq!(data.len(), PAGE_SIZE as usize);
    Ok(data)
}

fn to_base64<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded_v = Vec::new();
    let mut encoder = Encoder::new(encoded_v).unwrap();
    encoder.write_all(v).unwrap();
    let res = encoder.finish().into_result().unwrap();
    let b64_encoded = general_purpose::STANDARD.encode(res);
    serializer.serialize_str(&b64_encoded)
}

// The renaming below keeps compatibility with OP Cannon's state format
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct State {
    pub memory: Vec<Page>,
    #[serde(
        rename = "preimageKey",
        deserialize_with = "deserialize_preimage_key",
        serialize_with = "serialize_preimage_key"
    )]
    pub preimage_key: [u8; 32],
    #[serde(rename = "preimageOffset")]
    pub preimage_offset: u32,
    pub pc: u32,
    #[serde(rename = "nextPC")]
    pub next_pc: u32,
    pub lo: u32,
    pub hi: u32,
    pub heap: u32,
    pub exit: u8,
    pub exited: bool,
    pub step: u64,
    pub registers: [u32; 32],
    pub last_hint: Option<Vec<u8>>,
    pub preimage: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsePreimageKeyError(String);

#[derive(Debug, PartialEq)]
pub struct PreimageKey(pub [u8; 32]);

use std::str::FromStr;

impl FromStr for PreimageKey {
    type Err = ParsePreimageKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('x').collect::<Vec<&str>>();
        let hex_value: &str = if parts.len() == 1 {
            parts[0]
        } else {
            if parts.len() != 2 {
                return Err(ParsePreimageKeyError(
                    format!("Badly structured value to convert {s}").to_string(),
                ));
            };
            parts[1]
        };
        // We only handle a hexadecimal representations of exactly 32 bytes (no auto-padding)
        if hex_value.len() == 64 {
            hex::decode(hex_value).map_or_else(
                |_| {
                    Err(ParsePreimageKeyError(
                        format!("Could not hex decode {hex_value}").to_string(),
                    ))
                },
                |h| {
                    h.clone().try_into().map_or_else(
                        |_| {
                            Err(ParsePreimageKeyError(
                                format!("Could not cast vector {:#?} into 32 bytes array", h)
                                    .to_string(),
                            ))
                        },
                        |res| Ok(PreimageKey(res)),
                    )
                },
            )
        } else {
            Err(ParsePreimageKeyError(
                format!("{hex_value} is not 32-bytes long").to_string(),
            ))
        }
    }
}

fn deserialize_preimage_key<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let p = PreimageKey::from_str(s.as_str())
        .unwrap_or_else(|_| panic!("Parsing {s} as preimage key failed"));
    Ok(p.0)
}

fn serialize_preimage_key<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s: String = format!("0x{}", hex::encode(v));
    serializer.serialize_str(&s)
}

#[derive(Clone, Debug, PartialEq)]
pub enum StepFrequency {
    Never,
    Always,
    Exactly(u64),
    Every(u64),
    Range(u64, Option<u64>),
}

impl FromStr for StepFrequency {
    type Err = String;
    // Simple parser for Cannon's "frequency format"
    // A frequency input is either
    // - never/always
    // - =<n> (only at step n)
    // - %<n> (every steps multiple of n)
    // - n..[m] (from n on, until m excluded if specified, until the end otherwise)
    fn from_str(s: &str) -> std::result::Result<StepFrequency, String> {
        use StepFrequency::*;

        let mod_re = Regex::new(r"^%([0-9]+)").unwrap();
        let eq_re = Regex::new(r"^=([0-9]+)").unwrap();
        let ival_re = Regex::new(r"^([0-9]+)..([0-9]+)?").unwrap();

        match s {
            "never" => Ok(Never),
            "always" => Ok(Always),
            s => {
                if let Some(m) = mod_re.captures(s) {
                    Ok(Every(m[1].parse::<u64>().unwrap()))
                } else if let Some(m) = eq_re.captures(s) {
                    Ok(Exactly(m[1].parse::<u64>().unwrap()))
                } else if let Some(m) = ival_re.captures(s) {
                    let lo = m[1].parse::<u64>().unwrap();
                    let hi_opt = m.get(2).map(|x| x.as_str().parse::<u64>().unwrap());
                    Ok(Range(lo, hi_opt))
                } else {
                    Err(format!("Unknown frequency format {}", s))
                }
            }
        }
    }
}

impl Display for State {
    // A very debatable and incomplete, but serviceable, `to_string` implementation.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f,
            "memory_size (length): {}\nfirst page size: {}\npreimage key: {:#?}\npreimage offset:{}\npc: {}\nlo: {}\nhi: {}\nregisters:{:#?} ",
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
    pub metadata_file: Option<String>,
    pub proof_at: StepFrequency,
    pub stop_at: StepFrequency,
    pub snapshot_state_at: StepFrequency,
    pub info_at: StepFrequency,
    pub proof_fmt: String,
    pub snapshot_fmt: String,
    pub pprof_cpu: bool,
    pub halt_address: Option<u32>,
    pub host: Option<HostProgram>,
}

impl Default for VmConfiguration {
    fn default() -> Self {
        VmConfiguration {
            input_state_file: "state.json".to_string(),
            output_state_file: "out.json".to_string(),
            metadata_file: None,
            proof_at: StepFrequency::Never,
            stop_at: StepFrequency::Never,
            snapshot_state_at: StepFrequency::Never,
            info_at: StepFrequency::Never,
            proof_fmt: "proof-%d.json".to_string(),
            snapshot_fmt: "state-%d.json".to_string(),
            pprof_cpu: false,
            halt_address: None,
            host: None,
        }
    }
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
    #[serde(deserialize_with = "filtered_ordered")]
    pub symbols: Vec<Symbol>, // Needs to be in ascending order w.r.t start address
}

// Make sure that deserialized data are ordered in ascending order and that we
// have removed 0-size symbols
fn filtered_ordered<'de, D>(deserializer: D) -> Result<Vec<Symbol>, D::Error>
where
    D: Deserializer<'de>,
{
    let v: Vec<Symbol> = Deserialize::deserialize(deserializer)?;
    let mut filtered: Vec<Symbol> = v.into_iter().filter(|e| e.size != 0).collect();
    filtered.sort_by(|a, b| a.start.cmp(&b.start));
    Ok(filtered)
}

impl Meta {
    pub fn find_address_symbol(&self, address: u32) -> Option<String> {
        use std::cmp::Ordering;

        self.symbols
            .binary_search_by(
                |Symbol {
                     start,
                     size,
                     name: _,
                 }| {
                    if address < *start {
                        Ordering::Greater
                    } else {
                        let end = *start + *size as u32;
                        if address >= end {
                            Ordering::Less
                        } else {
                            Ordering::Equal
                        }
                    }
                },
            )
            .map_or_else(|_| None, |idx| Some(self.symbols[idx].name.to_string()))
    }
}

pub const HINT_CLIENT_READ_FD: i32 = 3;
pub const HINT_CLIENT_WRITE_FD: i32 = 4;
pub const PREIMAGE_CLIENT_READ_FD: i32 = 5;
pub const PREIMAGE_CLIENT_WRITE_FD: i32 = 6;

pub struct Preimage(Vec<u8>);

impl Preimage {
    pub fn create(v: Vec<u8>) -> Self {
        Preimage(v)
    }

    pub fn get(self) -> Vec<u8> {
        self.0
    }
}

pub struct Hint(Vec<u8>);

impl Hint {
    pub fn create(v: Vec<u8>) -> Self {
        Hint(v)
    }

    pub fn get(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::{
        fs::File,
        io::{BufReader, Write},
    };

    #[test]
    fn sp_parser() {
        use StepFrequency::*;
        assert_eq!(StepFrequency::from_str("never"), Ok(Never));
        assert_eq!(StepFrequency::from_str("always"), Ok(Always));
        assert_eq!(StepFrequency::from_str("=123"), Ok(Exactly(123)));
        assert_eq!(StepFrequency::from_str("%123"), Ok(Every(123)));
        assert_eq!(StepFrequency::from_str("1..3"), Ok(Range(1, Some(3))));
        assert_eq!(StepFrequency::from_str("1.."), Ok(Range(1, None)));
        assert!(StepFrequency::from_str("@123").is_err());
    }

    // This sample is a subset taken from a Cannon-generated "meta.json" file
    // Interestingly, it contains 0-size symbols - there are removed by
    // deserialization.
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
    },  
    {
      "name": "runtime/internal/atomic.(*Uint8).Load",
      "start": 71504,
      "size": 28
    },
    {
      "name": "runtime/internal/atomic.(*Uint8).Store",
      "start": 71532,
      "size": 28
    },
    {
      "name": "runtime/internal/atomic.(*Uint8).And",
      "start": 71560,
      "size": 88
    },
    {
      "name": "runtime/internal/atomic.(*Uint8).Or",
      "start": 71648,
      "size": 72
    }]}"#;

    fn deserialize_meta_sample() -> Meta {
        serde_json::from_str::<Meta>(META_SAMPLE).unwrap()
    }

    #[test]
    fn test_serialize_deserialize_page() {
        let value: &str = r#"{"index":16,"data":"eJztlkFoE0EUht8k21ZEtFYFg1FCTW0qSGoTS6pFJU3TFlNI07TEQJHE1kJMmhwi1ihaRJCqiAdBKR5Ez4IXvQk5eBaP4iEWpAchV0Hoof5vd14SoQcvve0H/5s3O//OzuzMLHtvNBZVDkUNHLQLUdHugSTKINJgnDoNZB60+MhFBq63Q0G4LCFYQptZoKR9r0hpEc1r4bopy8WRtdptmCJqM+t89RHiY60Xc39M8b26XXUjHLdEbf4qdTyMIWvn9vnyxhTy7eBxGwvGoRWU23ASIqNE5MT4H2DslogOa/EY+f38LxiNKYyrEwW02sV9CJLfgdjnMOfLc0+6biMKHohJFLe2fqO0qLl4Hui0AfcB1H0EzEFTc73GtSfIBO0jnhvnDvpx5CLVIJoKoS7Ic59C2pdfoRpEe+KoC+J7CWnf8leqQf/CbcwbiHP2rcO3TuENfr+C9HcGYp+T15nXnMjdOl/JOyDtc3tUt9tDzto31AXprwuyfCc2SfVsohZ8j7ogPh4Lr7NT+fxV1Yv9pXJ11AXxHYUsX99aVfnWqkT11vcsvk8QnstWJD4EUr0Igt4HqodD0wdP59kIUkH76DvU9IXOXSfnr0tIBe1T5zlAJmrY+xHFICRIG+8p5Lq/YW+djt1tfX/S314ODV/67Wc6eOEZUkF8CxwavqWfSWo/9QWpoH2UhXjtHDhn+E6wzO+EIL4RnEk+nOzDnmWZayRYDyJ6BzkgE3Vjv5faYrjV9F6DuD/eMx+gxvlQlbnndMDdh1TA2G1sbGxsbGxsbGx2Co9Sqvk/2gL/r05DxlgRP8bZK0O50cJQPjMxO5HKhCOlQr8/sVy5uRTuD5RGKuXFaDgYSQ+E/LOlsZlEIZ8NBqKlcmby8mIpPOjPpWYmxwPF06lI+mpqPB+O35ou0l+FGHpe"}"#;
        let decoded_page: Page = serde_json::from_str(value).unwrap();
        let res = serde_json::to_string(&decoded_page).unwrap();
        assert_eq!(res, value);
    }

    #[test]
    fn test_preimage_key_serialisation() {
        #[derive(Serialize, Deserialize)]
        struct TestPreimageKeyStruct {
            #[serde(
                rename = "preimageKey",
                deserialize_with = "deserialize_preimage_key",
                serialize_with = "serialize_preimage_key"
            )]
            pub preimage_key: [u8; 32],
        }

        let preimage_key: &str = r#"{"preimageKey":"0x0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let s: TestPreimageKeyStruct = serde_json::from_str(preimage_key).unwrap();
        let res = serde_json::to_string(&s).unwrap();
        assert_eq!(preimage_key, res);
    }

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
                    name: "internal/cpu.processOptions".to_string(),
                    start: 69632,
                    size: 1872,
                },
                Symbol {
                    name: "runtime/internal/atomic.(*Uint8).Load".to_string(),
                    start: 71504,
                    size: 28,
                },
                Symbol {
                    name: "runtime/internal/atomic.(*Uint8).Store".to_string(),
                    start: 71532,
                    size: 28,
                },
                Symbol {
                    name: "runtime/internal/atomic.(*Uint8).And".to_string(),
                    start: 71560,
                    size: 88,
                },
                Symbol {
                    name: "runtime/internal/atomic.(*Uint8).Or".to_string(),
                    start: 71648,
                    size: 72,
                },
            ],
        };

        assert_eq!(read, expected);
    }

    #[test]
    fn test_find_address_symbol() {
        let meta = deserialize_meta_sample();

        assert_eq!(
            meta.find_address_symbol(69633),
            Some("internal/cpu.processOptions".to_string())
        );
        assert_eq!(
            meta.find_address_symbol(69632),
            Some("internal/cpu.processOptions".to_string())
        );
        assert_eq!(meta.find_address_symbol(42), None);
    }

    #[test]
    fn test_parse_preimagekey() {
        assert_eq!(
            PreimageKey::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            ),
            Ok(PreimageKey([0; 32]))
        );
        assert_eq!(
            PreimageKey::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ),
            Ok(PreimageKey([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ]))
        );
        assert!(PreimageKey::from_str("0x01").is_err());
    }
}
