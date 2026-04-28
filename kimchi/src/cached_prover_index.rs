//! mmap-backed proving-key cache.
//!
//! The cache file is a self-describing binary layout:
//!
//! 1. File magic + format version + ark-ff version + identifier.
//! 2. Fixed-size `ScalarHeader` holding all small POD metadata (public input
//!    count, zk_rows, domain sizes + generators, endo, shift, etc.).
//! 3. A section table pointing at variable-length POD payload sections
//!    (sid, pruned gates, column evaluation arrays, lookup arrays).
//!
//! The readable side [`CachedProverIndex`] holds an `Arc<memmap2::Mmap>` plus
//! precomputed slice references into the mapping. Field-element accesses do
//! not allocate; the OS page cache handles eviction under pressure.
//!
//! See `CLAUDE.local.md` and the design doc for the full data bundle audit.
//!
//! Only available with the `mmap_cache` feature.

use ark_ff::PrimeField;
use std::fmt;

use crate::circuits::wires::PERMUTS;

/// Magic bytes at file offset 0. Distinct from any existing cache format in
/// the Mina stack so a wrong file is rejected immediately.
pub const FILE_MAGIC: [u8; 8] = *b"MINAPK01";

/// Current on-disk layout version. Bump on any incompatible change.
///
/// Version 2 switched field-element encoding from canonical form to
/// Montgomery form so that the on-disk bytes match `Fp`'s in-memory
/// layout exactly. That lets the reader construct `Vec<F>` via
/// `Vec::from_raw_parts` pointing into the mmap (zero-copy), instead of
/// running a per-element Montgomery reduction on load.
pub const FORMAT_VERSION: u32 = 2;

/// Maximum length (in bytes) of the caller-supplied identifier stored in the
/// file header. Sized to comfortably accommodate sha512 hex (128 bytes) plus
/// a caller prefix. Stored length-prefixed inside a fixed-size field so the
/// header layout is constant regardless of identifier length.
pub const IDENTIFIER_MAX_LEN: usize = 512;

/// Maximum length of the ark-ff version string recorded in the header.
pub const ARK_FF_VERSION_MAX_LEN: usize = 32;

/// Alignment (in bytes) applied to every payload section. Chosen as 32 to
/// match the natural alignment of an `ark_ff::BigInt<4>` (four `u64` limbs),
/// allowing zero-copy `&[F]` casts via `from_raw_parts` without misalignment.
pub const SECTION_ALIGNMENT: usize = 32;

/// Size of one field element on disk: four little-endian `u64` limbs of
/// Montgomery representation.
pub const FIELD_ELEMENT_BYTES: usize = 32;

// Compile-time sanity: we rely on little-endian hosts for direct byte-level
// access into the mmap. Abort the build on big-endian targets rather than
// silently corrupting data.
#[cfg(target_endian = "big")]
compile_error!(
    "cached_prover_index requires a little-endian target; the on-disk \
     layout stores field-element limbs as little-endian u64."
);

/// Tags identifying the different payload sections in the section table.
/// Tag values are stable across format versions within the same major
/// version and must never be reused for a different meaning.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SectionTag {
    /// `sid: Vec<F>`.
    Sid = 0x01,
    /// Packed `[PrunedGate]` array.
    Gates = 0x02,
    /// Coefficients 0..14 over domain d8 (one tag per column).
    Coefficients8Base = 0x10,
    /// Generic-gate selector over domain d4.
    GenericSelector4 = 0x20,
    /// Poseidon-gate selector over domain d8.
    PoseidonSelector8 = 0x21,
    /// Complete-add selector over domain d4.
    CompleteAddSelector4 = 0x22,
    /// Variable-base scalar-mul selector over domain d8.
    MulSelector8 = 0x23,
    /// Endo scalar-mul selector over domain d8.
    EmulSelector8 = 0x24,
    /// Endo-mul-scalar selector over domain d8.
    EndomulScalarSelector8 = 0x25,
    /// Permutation coefficients 0..6 over domain d8 (one tag per column).
    PermutationCoefficients8Base = 0x30,
    /// Optional RangeCheck0 selector over domain d8.
    RangeCheck0Selector8 = 0x40,
    /// Optional RangeCheck1 selector over domain d8.
    RangeCheck1Selector8 = 0x41,
    /// Optional ForeignFieldAdd selector over domain d8.
    ForeignFieldAddSelector8 = 0x42,
    /// Optional ForeignFieldMul selector over domain d8.
    ForeignFieldMulSelector8 = 0x43,
    /// Optional Xor16 selector over domain d8.
    XorSelector8 = 0x44,
    /// Optional Rot64 selector over domain d8.
    RotSelector8 = 0x45,
    /// Concatenated `lookup_table8` payload: `count × d8_size × 32` bytes
    /// of field elements. The count of inner arrays is stored in the
    /// section-table entry's `elem_domain_size`, keeping the payload
    /// 32-byte aligned for zero-copy slice construction.
    LookupTable8 = 0x50,
    /// `table_ids8` over d8. Present iff `LookupSelectorBits::TABLE_IDS8`.
    TableIds8 = 0x51,
    /// `lookup_selectors.xor` over d8. Presence per `LookupSelectorBits`.
    LookupSelectorXor = 0x52,
    /// `lookup_selectors.lookup` over d8.
    LookupSelectorLookup = 0x53,
    /// `lookup_selectors.range_check` over d8.
    LookupSelectorRangeCheck = 0x54,
    /// `lookup_selectors.ffmul` over d8.
    LookupSelectorFfmul = 0x55,
    /// `runtime_selector` over d8.
    RuntimeSelector8 = 0x56,
    /// `runtime_tables` spec: `u32` count, then `count × (id:i32, len:u32)`.
    RuntimeTablesSpec = 0x57,
    /// `runtime_table_offset`: 8-byte little-endian u64.
    RuntimeTableOffset = 0x58,
}

impl SectionTag {
    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// Returns the section tag for the `i`-th coefficient column (0..=14).
pub fn coefficient_tag(i: usize) -> u32 {
    assert!(i < 15, "coefficient index out of range");
    SectionTag::Coefficients8Base as u32 + i as u32
}

/// Returns the section tag for the `i`-th permutation coefficient column
/// (0..=6).
pub fn permutation_coefficient_tag(i: usize) -> u32 {
    assert!(i < PERMUTS, "permutation coefficient index out of range");
    SectionTag::PermutationCoefficients8Base as u32 + i as u32
}

/// Fixed-size header holding all scalar-valued metadata.
///
/// Packed explicitly via a fixed byte layout rather than `#[repr(C)]` to keep
/// the on-disk format independent of Rust's layout algorithm. All integer
/// fields are little-endian; field elements are stored as four LE `u64`
/// limbs matching `ark_ff::BigInt<4>`.
#[derive(Clone, Debug)]
pub struct ScalarHeader {
    pub public: u32,
    pub prev_challenges: u32,
    pub zk_rows: u64,
    pub max_poly_size: u64,
    pub disable_gates_checks: bool,
    /// `d1` domain size. `d2`, `d4`, `d8` are deterministic derivatives of
    /// `d1` under `Radix2EvaluationDomain::new`, so they are not serialized.
    pub domain_d1_size: u64,
    /// Feature flags packed into a u32 bitmap. See [`FeatureFlagBits`].
    pub feature_flags: u32,
    /// Bitmap of which optional `ColumnEvaluations` selectors are present.
    /// See [`OptionalSelectorBits`].
    pub optional_selectors_present: u32,
    /// Bitmap of which lookup selectors are present.
    pub lookup_selectors_present: u32,
    /// Whether the verifier_index_digest field below is populated.
    pub has_verifier_index_digest: bool,
    /// Group endomorphism coefficient, as 4 LE u64 limbs.
    pub endo_limbs: [u64; 4],
    /// Wire coordinate shifts, one per permutation column.
    pub shift_limbs: [[u64; 4]; PERMUTS],
    /// Optional verifier_index_digest field (populated iff
    /// `has_verifier_index_digest`).
    pub verifier_index_digest_limbs: [u64; 4],
}

impl ScalarHeader {
    /// Serialized size in bytes. Must stay stable across format
    /// `FORMAT_VERSION` revisions.
    pub const SERIALIZED_SIZE: usize = 4   // public
        + 4   // prev_challenges
        + 8   // zk_rows
        + 8   // max_poly_size
        + 1   // disable_gates_checks
        + 7   // padding to 8-byte boundary
        + 8   // domain_d1_size
        + 4   // feature_flags
        + 4   // optional_selectors_present
        + 4   // lookup_selectors_present
        + 1   // has_verifier_index_digest
        + 3   // padding
        + 32  // endo_limbs
        + 32 * PERMUTS // shift_limbs
        + 32; // verifier_index_digest_limbs
}

/// Feature-flag bits packed into `ScalarHeader::feature_flags`.
pub struct FeatureFlagBits;
impl FeatureFlagBits {
    pub const RANGE_CHECK_0: u32 = 1 << 0;
    pub const RANGE_CHECK_1: u32 = 1 << 1;
    pub const FOREIGN_FIELD_ADD: u32 = 1 << 2;
    pub const FOREIGN_FIELD_MUL: u32 = 1 << 3;
    pub const XOR: u32 = 1 << 4;
    pub const ROT: u32 = 1 << 5;
    pub const LOOKUP_PATTERN_XOR: u32 = 1 << 8;
    pub const LOOKUP_PATTERN_LOOKUP: u32 = 1 << 9;
    pub const LOOKUP_PATTERN_RANGE_CHECK: u32 = 1 << 10;
    pub const LOOKUP_PATTERN_FOREIGN_FIELD_MUL: u32 = 1 << 11;
    pub const LOOKUP_JOINT_USED: u32 = 1 << 12;
    pub const LOOKUP_USES_RUNTIME_TABLES: u32 = 1 << 13;
}

/// Bits indicating which optional column-evaluation selectors are stored.
pub struct OptionalSelectorBits;
impl OptionalSelectorBits {
    pub const RANGE_CHECK_0: u32 = 1 << 0;
    pub const RANGE_CHECK_1: u32 = 1 << 1;
    pub const FOREIGN_FIELD_ADD: u32 = 1 << 2;
    pub const FOREIGN_FIELD_MUL: u32 = 1 << 3;
    pub const XOR: u32 = 1 << 4;
    pub const ROT: u32 = 1 << 5;
}

/// Bits indicating which optional `LookupConstraintSystem` sections are
/// stored, packed into `ScalarHeader::lookup_selectors_present`.
pub struct LookupSelectorBits;
impl LookupSelectorBits {
    pub const TABLE_IDS8: u32 = 1 << 0;
    pub const SELECTOR_XOR: u32 = 1 << 1;
    pub const SELECTOR_LOOKUP: u32 = 1 << 2;
    pub const SELECTOR_RANGE_CHECK: u32 = 1 << 3;
    pub const SELECTOR_FFMUL: u32 = 1 << 4;
    pub const RUNTIME_SELECTOR: u32 = 1 << 5;
    pub const RUNTIME_TABLES: u32 = 1 << 6;
    pub const RUNTIME_TABLE_OFFSET: u32 = 1 << 7;
}

/// A gate record stripped down to the fields the prover reads at prove
/// time: type tag and wire targets. Coefficients are deliberately omitted
/// because they are folded into `ColumnEvaluations::coefficients8` at key
/// generation time.
///
/// Wire coordinates are stored as `u32` rather than the in-memory `usize`
/// so that the on-disk layout is identical on 32-bit and 64-bit hosts.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrunedGate {
    /// Discriminant matching [`crate::circuits::gate::GateType`]. Stored as
    /// u16 for compactness; the enum currently has < 32 variants.
    pub typ_tag: u16,
    /// Explicit padding to keep the layout stable across compilers.
    _pad: [u8; 2],
    /// Wire targets: (row, col) for each of the 7 permutation columns.
    pub wires: [PrunedWire; PERMUTS],
}

impl PrunedGate {
    pub const fn new(typ_tag: u16, wires: [PrunedWire; PERMUTS]) -> Self {
        Self {
            typ_tag,
            _pad: [0; 2],
            wires,
        }
    }
}

/// On-disk form of [`crate::circuits::wires::Wire`]: 4-byte row, 4-byte col.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrunedWire {
    pub row: u32,
    pub col: u32,
}

impl PrunedWire {
    pub const fn new(row: u32, col: u32) -> Self {
        Self { row, col }
    }
}

/// One entry in the section table.
#[derive(Clone, Copy, Debug)]
pub struct SectionEntry {
    pub tag: u32,
    /// Byte offset from the start of the file.
    pub offset: u64,
    /// Length in bytes of the payload.
    pub length: u64,
    /// Domain size (number of field elements) for payload sections that are
    /// `Evaluations<F, D<F>>`. 0 for sections that are not evaluations.
    pub elem_domain_size: u32,
    /// Reserved for future use; must be zero on write.
    pub _reserved: u32,
}

impl SectionEntry {
    pub const SERIALIZED_SIZE: usize = 4 + 8 + 8 + 4 + 4;
}

/// Errors surfaced by the cache read/write paths.
#[derive(Debug)]
pub enum CacheError {
    Io(std::io::Error),
    BadMagic { found: [u8; 8] },
    UnsupportedFormatVersion { found: u32, supported: u32 },
    ArkFfVersionMismatch { found: String, expected: String },
    IdentifierTooLong { len: usize, max: usize },
    IdentifierMismatch { found: String, expected: String },
    IdentifierInvalidUtf8,
    DuplicateSectionTag { tag: u32 },
    MissingSection { tag: u32 },
    SectionLengthMismatch { tag: u32, expected: u64, found: u64 },
    MisalignedSection { tag: u32, offset: u64 },
    TruncatedFile,
    /// Field element count in a payload does not divide the payload length
    /// cleanly.
    PayloadNotFieldAligned { tag: u32, length: u64 },
    /// `ark_ff::BigInt<4>` size assumption was violated at runtime.
    BigIntSizeMismatch,
    /// `ConstraintSystem::feature_flags` bitmap had an unknown bit set.
    UnknownFeatureFlagBits { bits: u32 },
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Io(e) => write!(f, "i/o error: {e}"),
            CacheError::BadMagic { found } => {
                write!(f, "bad file magic: {found:?} (expected {FILE_MAGIC:?})")
            }
            CacheError::UnsupportedFormatVersion { found, supported } => write!(
                f,
                "unsupported cache format version {found} (this build supports {supported})"
            ),
            CacheError::ArkFfVersionMismatch { found, expected } => write!(
                f,
                "ark-ff version mismatch: file declares {found}, binary was built with {expected}"
            ),
            CacheError::IdentifierTooLong { len, max } => {
                write!(f, "identifier length {len} exceeds maximum {max}")
            }
            CacheError::IdentifierMismatch { found, expected } => write!(
                f,
                "cache file identifier mismatch: file contains {found:?}, caller provided {expected:?}"
            ),
            CacheError::IdentifierInvalidUtf8 => write!(f, "cache file identifier is not valid UTF-8"),
            CacheError::DuplicateSectionTag { tag } => {
                write!(f, "duplicate section tag {tag:#x} in section table")
            }
            CacheError::MissingSection { tag } => {
                write!(f, "required section tag {tag:#x} missing from section table")
            }
            CacheError::SectionLengthMismatch { tag, expected, found } => write!(
                f,
                "section {tag:#x} length mismatch: expected {expected}, found {found}"
            ),
            CacheError::MisalignedSection { tag, offset } => write!(
                f,
                "section {tag:#x} offset {offset} is not {SECTION_ALIGNMENT}-byte aligned"
            ),
            CacheError::TruncatedFile => write!(f, "cache file truncated before end of declared payload"),
            CacheError::PayloadNotFieldAligned { tag, length } => write!(
                f,
                "section {tag:#x} payload length {length} is not a multiple of {FIELD_ELEMENT_BYTES}"
            ),
            CacheError::BigIntSizeMismatch => {
                write!(f, "ark_ff::BigInt<4> is not 32 bytes on this build")
            }
            CacheError::UnknownFeatureFlagBits { bits } => {
                write!(f, "unknown bits {bits:#x} in feature-flags bitmap")
            }
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CacheError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e)
    }
}

/// The ark-ff version string recorded in cache files produced by this
/// binary. Read back at open time and compared to the reader's version;
/// mismatched readers reject the file rather than silently corrupting.
pub const ARK_FF_VERSION: &str = "ark-ff-0.5";

/// Rounds `n` up to the nearest multiple of `SECTION_ALIGNMENT`.
pub fn align_up(n: usize) -> usize {
    (n + SECTION_ALIGNMENT - 1) & !(SECTION_ALIGNMENT - 1)
}

/// Padding required after a byte-run of length `n` to reach section
/// alignment.
pub fn alignment_padding(n: usize) -> usize {
    align_up(n) - n
}

/// Returns the four LE u64 Montgomery-form limbs underlying `f`.
///
/// `ark-ff 0.5` defines `Fp<P, 4>(pub BigInt<4>, pub PhantomData<P>)` and
/// `BigInt<4>(pub [u64; 4])`. Rust's default layout for a struct with one
/// non-ZST field lays those out identically to `[u64; 4]`, and the
/// `.0.0` path exposes the Montgomery limbs directly. `PrimeField`
/// doesn't expose that path generically, so we do the reinterpretation
/// via raw-pointer read after asserting the size and alignment invariants
/// the cache relies on everywhere.
///
/// Reading Montgomery limbs is crucial for zero-copy: the on-disk bytes
/// stored by [`write_field_slice`] must match `Fp`'s in-memory layout
/// exactly so [`mmap_field_vec`] can reinterpret the mapped bytes
/// directly. If we stored the canonical form (via `into_bigint`) the
/// mmap-backed Vec would contain values that look like canonical but
/// the prover would treat as Montgomery — silent corruption.
pub fn field_to_limbs<F: PrimeField>(f: &F) -> [u64; 4] {
    debug_assert_eq!(
        core::mem::size_of::<F>(),
        FIELD_ELEMENT_BYTES,
        "field_to_limbs assumes F has the memory layout of [u64; 4]"
    );
    debug_assert_eq!(
        core::mem::align_of::<F>(),
        core::mem::align_of::<[u64; 4]>(),
        "field_to_limbs assumes F shares alignment with [u64; 4]"
    );
    // SAFETY: F is `Fp<MontBackend<..., 4>, 4>` in the Pasta stack, which
    // has the exact memory layout of `[u64; 4]` (see docstring). The
    // size + alignment debug asserts above protect against accidental
    // instantiations with a different layout.
    unsafe { core::ptr::read(f as *const F as *const [u64; 4]) }
}

/// Reconstructs a field element from its four LE u64 Montgomery-form
/// limbs. Inverse of [`field_to_limbs`]; see that function's docstring
/// for the layout assumptions.
pub fn limbs_to_field<F: PrimeField>(limbs: &[u64; 4]) -> F {
    debug_assert_eq!(
        core::mem::size_of::<F>(),
        FIELD_ELEMENT_BYTES,
        "limbs_to_field assumes F has the memory layout of [u64; 4]"
    );
    debug_assert_eq!(
        core::mem::align_of::<F>(),
        core::mem::align_of::<[u64; 4]>(),
        "limbs_to_field assumes F shares alignment with [u64; 4]"
    );
    // SAFETY: see `field_to_limbs`. `read` performs a bitwise copy; any
    // trailing padding in F's layout (there is none for Fp<P, 4>) would
    // be uninitialised, but since the Pasta Fp has no padding this is a
    // full-bytes read.
    unsafe { core::ptr::read(limbs as *const [u64; 4] as *const F) }
}

// Runtime assertion that the field-element layout assumption holds. Cheap
// and only paid once per process; protects against silently picking up an
// ark-ff upgrade that changes the representation.
pub(crate) fn assert_bigint_layout<F: PrimeField>() -> Result<(), CacheError> {
    if core::mem::size_of::<F::BigInt>() == FIELD_ELEMENT_BYTES {
        Ok(())
    } else {
        Err(CacheError::BigIntSizeMismatch)
    }
}

// ---------------------------------------------------------------------------
// Binary-layout helpers
// ---------------------------------------------------------------------------

/// Byte offset (from file start) of the `num_sections` u32 in the fixed
/// preamble. Callers outside this module shouldn't need this, but tests
/// sometimes do.
pub const PREAMBLE_SIZE: usize = 8   // magic
    + 4   // format_version
    + 4   // reserved_flags
    + ARK_FF_VERSION_MAX_LEN
    + 4   // identifier_len
    + IDENTIFIER_MAX_LEN
    + 4; // num_sections

/// Total file offset at which the section table begins (immediately after
/// the `ScalarHeader`).
pub const SECTION_TABLE_OFFSET: usize = PREAMBLE_SIZE + ScalarHeader::SERIALIZED_SIZE;

fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn read_u32_le(bytes: &[u8]) -> Result<(u32, &[u8]), CacheError> {
    if bytes.len() < 4 {
        return Err(CacheError::TruncatedFile);
    }
    let (head, tail) = bytes.split_at(4);
    let mut buf = [0u8; 4];
    buf.copy_from_slice(head);
    Ok((u32::from_le_bytes(buf), tail))
}

fn read_u64_le(bytes: &[u8]) -> Result<(u64, &[u8]), CacheError> {
    if bytes.len() < 8 {
        return Err(CacheError::TruncatedFile);
    }
    let (head, tail) = bytes.split_at(8);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(head);
    Ok((u64::from_le_bytes(buf), tail))
}

fn read_exact<'a>(bytes: &'a [u8], n: usize) -> Result<(&'a [u8], &'a [u8]), CacheError> {
    if bytes.len() < n {
        return Err(CacheError::TruncatedFile);
    }
    Ok(bytes.split_at(n))
}

/// Encodes `s` into a fixed-size zero-padded field. Errors if `s` is longer
/// than `max`.
fn pad_string(out: &mut Vec<u8>, s: &str, max: usize) -> Result<(), CacheError> {
    if s.len() > max {
        return Err(CacheError::IdentifierTooLong {
            len: s.len(),
            max,
        });
    }
    out.extend_from_slice(s.as_bytes());
    out.resize(out.len() + (max - s.len()), 0);
    Ok(())
}

/// Reads a zero-terminated UTF-8 string from a fixed-size field.
fn unpad_string(bytes: &[u8]) -> Result<&str, CacheError> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).map_err(|_| CacheError::IdentifierInvalidUtf8)
}

impl ScalarHeader {
    pub fn write(&self, out: &mut Vec<u8>) {
        write_u32_le(out, self.public);
        write_u32_le(out, self.prev_challenges);
        write_u64_le(out, self.zk_rows);
        write_u64_le(out, self.max_poly_size);
        out.push(self.disable_gates_checks as u8);
        // pad to 8-byte boundary
        out.extend_from_slice(&[0u8; 7]);
        write_u64_le(out, self.domain_d1_size);
        write_u32_le(out, self.feature_flags);
        write_u32_le(out, self.optional_selectors_present);
        write_u32_le(out, self.lookup_selectors_present);
        out.push(self.has_verifier_index_digest as u8);
        out.extend_from_slice(&[0u8; 3]);
        for limb in &self.endo_limbs {
            write_u64_le(out, *limb);
        }
        for row in &self.shift_limbs {
            for limb in row {
                write_u64_le(out, *limb);
            }
        }
        for limb in &self.verifier_index_digest_limbs {
            write_u64_le(out, *limb);
        }
    }

    pub fn read(bytes: &[u8]) -> Result<(Self, &[u8]), CacheError> {
        let (public, bytes) = read_u32_le(bytes)?;
        let (prev_challenges, bytes) = read_u32_le(bytes)?;
        let (zk_rows, bytes) = read_u64_le(bytes)?;
        let (max_poly_size, bytes) = read_u64_le(bytes)?;
        let (disable_b, bytes) = read_exact(bytes, 1)?;
        let disable_gates_checks = disable_b[0] != 0;
        let (_pad, bytes) = read_exact(bytes, 7)?;
        let (domain_d1_size, bytes) = read_u64_le(bytes)?;
        let (feature_flags, bytes) = read_u32_le(bytes)?;
        let (optional_selectors_present, bytes) = read_u32_le(bytes)?;
        let (lookup_selectors_present, bytes) = read_u32_le(bytes)?;
        let (has_vkd_b, bytes) = read_exact(bytes, 1)?;
        let has_verifier_index_digest = has_vkd_b[0] != 0;
        let (_pad, bytes) = read_exact(bytes, 3)?;
        let mut endo_limbs = [0u64; 4];
        let mut bytes = bytes;
        for limb in endo_limbs.iter_mut() {
            let (v, rest) = read_u64_le(bytes)?;
            *limb = v;
            bytes = rest;
        }
        let mut shift_limbs = [[0u64; 4]; PERMUTS];
        for row in shift_limbs.iter_mut() {
            for limb in row.iter_mut() {
                let (v, rest) = read_u64_le(bytes)?;
                *limb = v;
                bytes = rest;
            }
        }
        let mut verifier_index_digest_limbs = [0u64; 4];
        for limb in verifier_index_digest_limbs.iter_mut() {
            let (v, rest) = read_u64_le(bytes)?;
            *limb = v;
            bytes = rest;
        }
        Ok((
            Self {
                public,
                prev_challenges,
                zk_rows,
                max_poly_size,
                disable_gates_checks,
                domain_d1_size,
                feature_flags,
                optional_selectors_present,
                lookup_selectors_present,
                has_verifier_index_digest,
                endo_limbs,
                shift_limbs,
                verifier_index_digest_limbs,
            },
            bytes,
        ))
    }
}

impl SectionEntry {
    pub fn write(&self, out: &mut Vec<u8>) {
        write_u32_le(out, self.tag);
        write_u64_le(out, self.offset);
        write_u64_le(out, self.length);
        write_u32_le(out, self.elem_domain_size);
        write_u32_le(out, self._reserved);
    }

    pub fn read(bytes: &[u8]) -> Result<(Self, &[u8]), CacheError> {
        let (tag, bytes) = read_u32_le(bytes)?;
        let (offset, bytes) = read_u64_le(bytes)?;
        let (length, bytes) = read_u64_le(bytes)?;
        let (elem_domain_size, bytes) = read_u32_le(bytes)?;
        let (_reserved, bytes) = read_u32_le(bytes)?;
        Ok((
            Self {
                tag,
                offset,
                length,
                elem_domain_size,
                _reserved,
            },
            bytes,
        ))
    }
}

// ---------------------------------------------------------------------------
// Preamble writer/reader
// ---------------------------------------------------------------------------

fn write_preamble(
    out: &mut Vec<u8>,
    identifier: &str,
    num_sections: u32,
) -> Result<(), CacheError> {
    out.extend_from_slice(&FILE_MAGIC);
    write_u32_le(out, FORMAT_VERSION);
    write_u32_le(out, 0); // reserved flags
    pad_string(out, ARK_FF_VERSION, ARK_FF_VERSION_MAX_LEN)?;
    write_u32_le(out, identifier.len() as u32);
    pad_string(out, identifier, IDENTIFIER_MAX_LEN)?;
    write_u32_le(out, num_sections);
    Ok(())
}

/// Parsed preamble data, returned to the reader along with the tail slice.
pub struct Preamble {
    pub format_version: u32,
    pub ark_ff_version: String,
    pub identifier: String,
    pub num_sections: u32,
}

fn read_preamble(bytes: &[u8]) -> Result<(Preamble, &[u8]), CacheError> {
    let (magic, bytes) = read_exact(bytes, 8)?;
    let mut magic_arr = [0u8; 8];
    magic_arr.copy_from_slice(magic);
    if magic_arr != FILE_MAGIC {
        return Err(CacheError::BadMagic { found: magic_arr });
    }
    let (format_version, bytes) = read_u32_le(bytes)?;
    if format_version != FORMAT_VERSION {
        return Err(CacheError::UnsupportedFormatVersion {
            found: format_version,
            supported: FORMAT_VERSION,
        });
    }
    let (_reserved_flags, bytes) = read_u32_le(bytes)?;
    let (ark_ff, bytes) = read_exact(bytes, ARK_FF_VERSION_MAX_LEN)?;
    let ark_ff_version = unpad_string(ark_ff)?.to_owned();
    if ark_ff_version != ARK_FF_VERSION {
        return Err(CacheError::ArkFfVersionMismatch {
            found: ark_ff_version,
            expected: ARK_FF_VERSION.to_owned(),
        });
    }
    let (id_len, bytes) = read_u32_le(bytes)?;
    let (id_field, bytes) = read_exact(bytes, IDENTIFIER_MAX_LEN)?;
    let id_len_usize = id_len as usize;
    if id_len_usize > IDENTIFIER_MAX_LEN {
        return Err(CacheError::IdentifierTooLong {
            len: id_len_usize,
            max: IDENTIFIER_MAX_LEN,
        });
    }
    let identifier = core::str::from_utf8(&id_field[..id_len_usize])
        .map_err(|_| CacheError::IdentifierInvalidUtf8)?
        .to_owned();
    let (num_sections, bytes) = read_u32_le(bytes)?;
    Ok((
        Preamble {
            format_version,
            ark_ff_version,
            identifier,
            num_sections,
        },
        bytes,
    ))
}

// ---------------------------------------------------------------------------
// Feature-flag bitmap round-trip
// ---------------------------------------------------------------------------

use crate::circuits::constraints::FeatureFlags;
use crate::circuits::lookup::lookups::{LookupFeatures, LookupPatterns};

fn pack_feature_flags(flags: &FeatureFlags) -> u32 {
    let mut bits = 0u32;
    if flags.range_check0 {
        bits |= FeatureFlagBits::RANGE_CHECK_0;
    }
    if flags.range_check1 {
        bits |= FeatureFlagBits::RANGE_CHECK_1;
    }
    if flags.foreign_field_add {
        bits |= FeatureFlagBits::FOREIGN_FIELD_ADD;
    }
    if flags.foreign_field_mul {
        bits |= FeatureFlagBits::FOREIGN_FIELD_MUL;
    }
    if flags.xor {
        bits |= FeatureFlagBits::XOR;
    }
    if flags.rot {
        bits |= FeatureFlagBits::ROT;
    }
    if flags.lookup_features.patterns.xor {
        bits |= FeatureFlagBits::LOOKUP_PATTERN_XOR;
    }
    if flags.lookup_features.patterns.lookup {
        bits |= FeatureFlagBits::LOOKUP_PATTERN_LOOKUP;
    }
    if flags.lookup_features.patterns.range_check {
        bits |= FeatureFlagBits::LOOKUP_PATTERN_RANGE_CHECK;
    }
    if flags.lookup_features.patterns.foreign_field_mul {
        bits |= FeatureFlagBits::LOOKUP_PATTERN_FOREIGN_FIELD_MUL;
    }
    if flags.lookup_features.joint_lookup_used {
        bits |= FeatureFlagBits::LOOKUP_JOINT_USED;
    }
    if flags.lookup_features.uses_runtime_tables {
        bits |= FeatureFlagBits::LOOKUP_USES_RUNTIME_TABLES;
    }
    bits
}

fn unpack_feature_flags(bits: u32) -> Result<FeatureFlags, CacheError> {
    let known = FeatureFlagBits::RANGE_CHECK_0
        | FeatureFlagBits::RANGE_CHECK_1
        | FeatureFlagBits::FOREIGN_FIELD_ADD
        | FeatureFlagBits::FOREIGN_FIELD_MUL
        | FeatureFlagBits::XOR
        | FeatureFlagBits::ROT
        | FeatureFlagBits::LOOKUP_PATTERN_XOR
        | FeatureFlagBits::LOOKUP_PATTERN_LOOKUP
        | FeatureFlagBits::LOOKUP_PATTERN_RANGE_CHECK
        | FeatureFlagBits::LOOKUP_PATTERN_FOREIGN_FIELD_MUL
        | FeatureFlagBits::LOOKUP_JOINT_USED
        | FeatureFlagBits::LOOKUP_USES_RUNTIME_TABLES;
    let extra = bits & !known;
    if extra != 0 {
        return Err(CacheError::UnknownFeatureFlagBits { bits: extra });
    }
    Ok(FeatureFlags {
        range_check0: bits & FeatureFlagBits::RANGE_CHECK_0 != 0,
        range_check1: bits & FeatureFlagBits::RANGE_CHECK_1 != 0,
        foreign_field_add: bits & FeatureFlagBits::FOREIGN_FIELD_ADD != 0,
        foreign_field_mul: bits & FeatureFlagBits::FOREIGN_FIELD_MUL != 0,
        xor: bits & FeatureFlagBits::XOR != 0,
        rot: bits & FeatureFlagBits::ROT != 0,
        lookup_features: LookupFeatures {
            patterns: LookupPatterns {
                xor: bits & FeatureFlagBits::LOOKUP_PATTERN_XOR != 0,
                lookup: bits & FeatureFlagBits::LOOKUP_PATTERN_LOOKUP != 0,
                range_check: bits & FeatureFlagBits::LOOKUP_PATTERN_RANGE_CHECK != 0,
                foreign_field_mul: bits & FeatureFlagBits::LOOKUP_PATTERN_FOREIGN_FIELD_MUL != 0,
            },
            joint_lookup_used: bits & FeatureFlagBits::LOOKUP_JOINT_USED != 0,
            uses_runtime_tables: bits & FeatureFlagBits::LOOKUP_USES_RUNTIME_TABLES != 0,
        },
    })
}

// ---------------------------------------------------------------------------
// Field-element array (de)serialization
// ---------------------------------------------------------------------------

/// Serializes a slice of field elements as contiguous little-endian u64
/// limbs. Output length is `elements.len() * FIELD_ELEMENT_BYTES`.
fn write_field_slice<F: PrimeField>(out: &mut Vec<u8>, elements: &[F]) {
    for elt in elements {
        let limbs = field_to_limbs(elt);
        for limb in &limbs {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
}

/// Zero-copy: constructs a `Vec<F>` whose backing storage is the mmap
/// region itself, via `Vec::from_raw_parts(mmap_ptr, len, len)`.
///
/// # Safety
///
/// The returned `Vec<F>` **must never be dropped normally**. Vec's `Drop`
/// calls `Global::dealloc` on its pointer, which for this value points
/// into mmap memory — calling `dealloc` on that pointer is undefined
/// behaviour (it would try to free non-heap memory). Callers must keep
/// the returned `Vec<F>` inside a container whose own `Drop` either:
///
/// 1. Wraps the whole thing in [`core::mem::ManuallyDrop`] so the Vec's
///    `Drop` never runs (the approach used by [`MmapProverIndex`]), or
/// 2. Manually `mem::forget`s the Vec before the container drops.
///
/// The returned Vec also **must never grow**: a reallocation would call
/// the allocator to allocate and then copy-from/dealloc the old pointer.
/// Since the prover only reads field elements, this is fine in practice
/// but worth stating.
///
/// The caller is responsible for ensuring `bytes` is aligned for `F`
/// (8-byte aligned is sufficient for `BigInt<4>` — 32-byte section
/// alignment in the cache format covers this), and for keeping the
/// underlying mmap alive for the lifetime of the returned `Vec<F>`.
///
/// The byte slice must be exactly `count × FIELD_ELEMENT_BYTES` long.
unsafe fn mmap_field_vec<F: PrimeField>(
    bytes: &[u8],
    count: usize,
) -> Result<Vec<F>, CacheError> {
    let expected = count
        .checked_mul(FIELD_ELEMENT_BYTES)
        .ok_or(CacheError::TruncatedFile)?;
    if bytes.len() != expected {
        return Err(CacheError::PayloadNotFieldAligned {
            tag: 0,
            length: bytes.len() as u64,
        });
    }
    // Alignment check: `BigInt<4>` = `[u64; 4]` needs 8-byte alignment.
    // Section offsets are 32-byte aligned in the cache format so this
    // should always hold; assert it defensively.
    let align = core::mem::align_of::<F>();
    debug_assert!(
        (bytes.as_ptr() as usize) % align == 0,
        "mmap section pointer not aligned for F"
    );
    let ptr = bytes.as_ptr() as *mut F;
    // SAFETY: the caller contract forbids dropping or growing the
    // returned Vec; its lifetime must be bounded by the mmap's.
    Ok(Vec::from_raw_parts(ptr, count, count))
}

// ---------------------------------------------------------------------------
// GateType discriminant round-trip
// ---------------------------------------------------------------------------

use crate::circuits::gate::{CircuitGate, GateType};
use crate::circuits::wires::{GateWires, Wire};

fn gate_type_to_tag(t: GateType) -> u16 {
    // Matches the order declared in circuits/gate.rs. Kept in sync manually
    // so that ordering changes to GateType require a deliberate update here
    // (and, ideally, a FORMAT_VERSION bump).
    match t {
        GateType::Zero => 0,
        GateType::Generic => 1,
        GateType::Poseidon => 2,
        GateType::CompleteAdd => 3,
        GateType::VarBaseMul => 4,
        GateType::EndoMul => 5,
        GateType::EndoMulScalar => 6,
        GateType::Lookup => 7,
        GateType::RangeCheck0 => 8,
        GateType::RangeCheck1 => 9,
        GateType::ForeignFieldAdd => 10,
        GateType::ForeignFieldMul => 11,
        GateType::Xor16 => 12,
        GateType::Rot64 => 13,
    }
}

fn gate_type_from_tag(t: u16) -> Option<GateType> {
    Some(match t {
        0 => GateType::Zero,
        1 => GateType::Generic,
        2 => GateType::Poseidon,
        3 => GateType::CompleteAdd,
        4 => GateType::VarBaseMul,
        5 => GateType::EndoMul,
        6 => GateType::EndoMulScalar,
        7 => GateType::Lookup,
        8 => GateType::RangeCheck0,
        9 => GateType::RangeCheck1,
        10 => GateType::ForeignFieldAdd,
        11 => GateType::ForeignFieldMul,
        12 => GateType::Xor16,
        13 => GateType::Rot64,
        _ => return None,
    })
}

fn write_pruned_gate(out: &mut Vec<u8>, gate: &CircuitGate<impl PrimeField>) {
    let typ_tag = gate_type_to_tag(gate.typ);
    out.extend_from_slice(&typ_tag.to_le_bytes());
    out.extend_from_slice(&[0u8; 2]);
    for wire in &gate.wires {
        out.extend_from_slice(&(wire.row as u32).to_le_bytes());
        out.extend_from_slice(&(wire.col as u32).to_le_bytes());
    }
}

/// Byte size of one pruned gate record on disk. Must match
/// `write_pruned_gate` exactly.
pub const PRUNED_GATE_SIZE: usize = 2 + 2 + 2 * 4 * PERMUTS;

fn read_pruned_gate<F: PrimeField>(bytes: &[u8]) -> Result<CircuitGate<F>, CacheError> {
    if bytes.len() != PRUNED_GATE_SIZE {
        return Err(CacheError::TruncatedFile);
    }
    let mut typ_bytes = [0u8; 2];
    typ_bytes.copy_from_slice(&bytes[0..2]);
    let typ_tag = u16::from_le_bytes(typ_bytes);
    let typ = gate_type_from_tag(typ_tag)
        .ok_or(CacheError::UnknownFeatureFlagBits { bits: typ_tag as u32 })?;
    let mut wires: GateWires = [Wire::default(); PERMUTS];
    for i in 0..PERMUTS {
        let base = 4 + i * 8;
        let mut row_bytes = [0u8; 4];
        let mut col_bytes = [0u8; 4];
        row_bytes.copy_from_slice(&bytes[base..base + 4]);
        col_bytes.copy_from_slice(&bytes[base + 4..base + 8]);
        wires[i] = Wire {
            row: u32::from_le_bytes(row_bytes) as usize,
            col: u32::from_le_bytes(col_bytes) as usize,
        };
    }
    Ok(CircuitGate::new(typ, wires, Vec::new()))
}

// ---------------------------------------------------------------------------
// write_cache / read_cache
// ---------------------------------------------------------------------------

use crate::circuits::constraints::{ColumnEvaluations, ConstraintSystem};
use crate::circuits::domains::EvaluationDomains;
use crate::circuits::lookup::constraints::LookupConfiguration;
use crate::circuits::lookup::index::{LookupConstraintSystem, LookupSelectors};
use crate::circuits::lookup::lookups::LookupInfo;
use crate::circuits::lookup::runtime_tables::RuntimeTableSpec;
use crate::circuits::wires::COLUMNS;
use crate::curve::KimchiCurve;
use crate::linearization::expr_linearization;
use crate::o1_utils::lazy_cache::LazyCache;
use crate::prover_index::ProverIndex;
use ark_poly::{EvaluationDomain, Evaluations, Radix2EvaluationDomain};
use poly_commitment::SRS;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

/// Minimal read-only `MAP_SHARED` mmap wrapper built on libc. Keeps the
/// feature flag self-contained (no external `memmap2` crate required in
/// the kimchi-stubs vendored registry) and matches the subset of behavior
/// we need: open file, map read-only, munmap on drop.
struct ReadOnlyMmap {
    ptr: *const u8,
    len: usize,
}

// Safety: the mapping is read-only and the target is never shared across
// threads without external synchronization. We don't hand out `&mut`
// references into it, so Send + Sync match what the Rust stdlib gives for
// `&[u8]`.
unsafe impl Send for ReadOnlyMmap {}
unsafe impl Sync for ReadOnlyMmap {}

impl ReadOnlyMmap {
    fn map_file(file: &std::fs::File) -> std::io::Result<Self> {
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Ok(Self {
                ptr: core::ptr::NonNull::<u8>::dangling().as_ptr(),
                len: 0,
            });
        }
        // Safety: we pass a null addr (kernel chooses), a valid fd, and
        // check the return value against MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr as *const u8,
            len,
        })
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            // Safety: `ptr` + `len` were produced by a successful mmap and
            // the region is read-only. The lifetime is tied to `&self`.
            unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

impl Drop for ReadOnlyMmap {
    fn drop(&mut self) {
        if self.len != 0 {
            // Safety: matched pair with the mmap call; ignore errors (we
            // can't recover from a munmap failure in Drop).
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.len);
            }
        }
    }
}

impl<const FULL_ROUNDS: usize, G, Srs> MmapProverIndex<FULL_ROUNDS, G, Srs>
where
    G: KimchiCurve<FULL_ROUNDS>,
{
    /// Advise the kernel that the mapped cache file's pages are no longer
    /// needed (`MADV_DONTNEED`). Reads into the mapping after this call
    /// will trigger fresh page faults that re-populate from disk.
    ///
    /// This simulates the real-world behaviour the zero-copy cache was
    /// designed for — pages evicted under memory pressure are silently
    /// re-faulted as the prover walks back through them. Used in tests
    /// (see `cached_index_prove_after_madv_dontneed`) to confirm that the
    /// construction doesn't somehow keep the data pinned in RAM via a
    /// stray owned copy.
    ///
    /// No-op on a zero-length mapping.
    pub fn madvise_dontneed(&self) {
        if self._mmap.len == 0 {
            return;
        }
        // Safety: matched with the live mmap this wrapper owns; MADV_DONTNEED
        // on a MAP_SHARED read-only region just drops the resident pages
        // (next access faults them back in from the file). Errors here are
        // advisory — if the kernel rejects the hint we simply don't get
        // the eviction we asked for; nothing breaks.
        unsafe {
            libc::madvise(
                self._mmap.ptr as *mut libc::c_void,
                self._mmap.len,
                libc::MADV_DONTNEED,
            );
        }
    }
}

/// A [`ProverIndex`] whose large `Vec<F>` fields are backed by memory in a
/// live `mmap(2)` region instead of owned heap allocations.
///
/// The wrapper [`Deref`]s to `ProverIndex`, so anywhere the existing prover
/// takes `&ProverIndex` (e.g. `ProverProof::create`) it transparently
/// accepts an `MmapProverIndex` as well. The file pages can be evicted by
/// the kernel under memory pressure and re-faulted on demand.
///
/// # Lifetime and drop
///
/// The inner `ProverIndex` is stored in a [`ManuallyDrop`] because its
/// `Vec<F>` fields (sid; every `Evaluations.evals`; lookup data when
/// present) are constructed via `Vec::from_raw_parts(mmap_ptr, len, len)`
/// and point into the mapping. Running `Vec::drop` on them would call
/// `dealloc` on mmap memory, which is undefined behaviour.
///
/// Consequently, when `MmapProverIndex` is dropped, the inner
/// `ProverIndex`'s owned sub-allocations (the owned `gates` vector,
/// `linearization`, `powers_of_alpha`, and any LazyCache/Arc machinery)
/// leak. This is acceptable for Mina's usage pattern — proving keys are
/// loaded once at daemon startup and held for the life of the process,
/// so cumulative leakage is bounded and the OS reclaims everything on
/// exit. The `Arc<ReadOnlyMmap>` held alongside is dropped normally,
/// which calls `munmap` and releases the bulk of the key's memory.
///
/// A future refinement could replace the bulk leak with a manual per-
/// field tear-down: pattern-destructure the `ProverIndex`, drop the
/// owned fields explicitly, and `mem::forget` only the mmap-backed
/// Vecs. That's about 50 lines of `unsafe` and can be added without
/// affecting the on-disk format or the public API.
pub struct MmapProverIndex<const FULL_ROUNDS: usize, G: KimchiCurve<FULL_ROUNDS>, Srs> {
    index: core::mem::ManuallyDrop<ProverIndex<FULL_ROUNDS, G, Srs>>,
    _mmap: Arc<ReadOnlyMmap>,
}

impl<const FULL_ROUNDS: usize, G, Srs> core::ops::Deref
    for MmapProverIndex<FULL_ROUNDS, G, Srs>
where
    G: KimchiCurve<FULL_ROUNDS>,
{
    type Target = ProverIndex<FULL_ROUNDS, G, Srs>;
    fn deref(&self) -> &Self::Target {
        &self.index
    }
}

impl<const FULL_ROUNDS: usize, G, Srs> core::fmt::Debug
    for MmapProverIndex<FULL_ROUNDS, G, Srs>
where
    G: KimchiCurve<FULL_ROUNDS>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmapProverIndex")
            .field("mmap_len", &self._mmap.len)
            .finish_non_exhaustive()
    }
}

// The wrapper's thread-safety mirrors the wrapped ProverIndex. The mmap
// is read-only, so aliased reads from multiple threads are fine.
unsafe impl<const FULL_ROUNDS: usize, G, Srs> Send for MmapProverIndex<FULL_ROUNDS, G, Srs>
where
    G: KimchiCurve<FULL_ROUNDS>,
    ProverIndex<FULL_ROUNDS, G, Srs>: Send,
{
}
unsafe impl<const FULL_ROUNDS: usize, G, Srs> Sync for MmapProverIndex<FULL_ROUNDS, G, Srs>
where
    G: KimchiCurve<FULL_ROUNDS>,
    ProverIndex<FULL_ROUNDS, G, Srs>: Sync,
{
}

/// Context tracked during a cache-write to record sections in parallel with
/// the growing payload buffer.
struct WriteContext {
    payload: Vec<u8>,
    sections: Vec<SectionEntry>,
    /// File offset where payload section bytes will start. Set once the
    /// preamble + ScalarHeader + section table size is known.
    payload_base: u64,
}

impl WriteContext {
    fn new() -> Self {
        Self {
            payload: Vec::new(),
            sections: Vec::new(),
            payload_base: 0,
        }
    }

    /// Append a field-slice payload, record a `SectionEntry`, and apply
    /// trailing alignment padding so the next section starts 32-byte
    /// aligned.
    fn push_field_section<F: PrimeField>(
        &mut self,
        tag: u32,
        domain_size: u32,
        data: &[F],
    ) {
        let section_offset = self.payload_base + self.payload.len() as u64;
        let start = self.payload.len();
        write_field_slice(&mut self.payload, data);
        let length = (self.payload.len() - start) as u64;
        self.sections.push(SectionEntry {
            tag,
            offset: section_offset,
            length,
            elem_domain_size: domain_size,
            _reserved: 0,
        });
        let pad = alignment_padding(self.payload.len());
        self.payload.extend(std::iter::repeat(0u8).take(pad));
    }

    fn push_raw_section(&mut self, tag: u32, payload: &[u8]) {
        self.push_raw_section_with_elem_count(tag, 0, payload);
    }

    /// Like [`push_raw_section`] but records a caller-supplied value in the
    /// section-table entry's `elem_domain_size`. Used by `lookup_table8`,
    /// which encodes the count of inner evaluation arrays there rather
    /// than inline in the payload (inline would break the 32-byte
    /// alignment required for zero-copy field-element reads).
    fn push_raw_section_with_elem_count(
        &mut self,
        tag: u32,
        elem_domain_size: u32,
        payload: &[u8],
    ) {
        let section_offset = self.payload_base + self.payload.len() as u64;
        self.payload.extend_from_slice(payload);
        let length = payload.len() as u64;
        self.sections.push(SectionEntry {
            tag,
            offset: section_offset,
            length,
            elem_domain_size,
            _reserved: 0,
        });
        let pad = alignment_padding(self.payload.len());
        self.payload.extend(std::iter::repeat(0u8).take(pad));
    }
}

/// Computes the total bytes consumed by the fixed preamble + `ScalarHeader`
/// + section-table-for-`n`-sections + trailing alignment pad.
fn fixed_region_size(num_sections: usize) -> usize {
    let raw = PREAMBLE_SIZE + ScalarHeader::SERIALIZED_SIZE + num_sections * SectionEntry::SERIALIZED_SIZE;
    align_up(raw)
}

/// Writes a proving index to `path` in the mmap cache format.
///
/// The `identifier` is stored verbatim (bounded at `IDENTIFIER_MAX_LEN`
/// bytes) and must be supplied again on read for validation. Callers
/// typically pass a hash of the circuit's identifying key.
///
/// Writes are atomic: the file is staged at `path.tmp` and renamed into
/// place, so concurrent readers of an existing `path` see either the old
/// content or the new content but never a half-written file.
///
/// This function requires `G::ScalarField::BigInt` to be 32 bytes; the
/// assumption is checked at runtime (returns `BigIntSizeMismatch` on
/// violation).
pub fn write_cache<const FULL_ROUNDS: usize, G, Srs>(
    identifier: &str,
    index: &ProverIndex<FULL_ROUNDS, G, Srs>,
    path: &Path,
) -> Result<(), CacheError>
where
    G: KimchiCurve<FULL_ROUNDS>,
    Srs: SRS<G>,
    G::BaseField: PrimeField,
{
    assert_bigint_layout::<G::ScalarField>()?;
    if identifier.len() > IDENTIFIER_MAX_LEN {
        return Err(CacheError::IdentifierTooLong {
            len: identifier.len(),
            max: IDENTIFIER_MAX_LEN,
        });
    }

    let cs = &index.cs;
    // Grab the materialised LookupConstraintSystem (if any) once, up front.
    // A `Some(_)` here triggers emission of sections 0x50..0x58; `None` or a
    // `LookupError` leaves them out and keeps the file backward-compatible
    // with non-lookup readers.
    let lcs_result = cs.lookup_constraint_system.get();
    let lcs: Option<&LookupConstraintSystem<G::ScalarField>> = match lcs_result {
        Ok(opt) => opt.as_ref(),
        Err(_) => None,
    };

    // Build scalar header.
    let (vkd_limbs, has_vkd) = match index.verifier_index_digest.as_ref() {
        Some(digest) => (field_to_limbs(digest), true),
        None => ([0u64; 4], false),
    };

    let shift_limbs: [[u64; 4]; PERMUTS] = {
        let mut arr = [[0u64; 4]; PERMUTS];
        for (i, s) in cs.shift.iter().enumerate() {
            arr[i] = field_to_limbs(s);
        }
        arr
    };

    let column_evaluations = index.column_evaluations.get();
    let optional_selectors_present = {
        let mut bits = 0u32;
        if column_evaluations.range_check0_selector8.is_some() {
            bits |= OptionalSelectorBits::RANGE_CHECK_0;
        }
        if column_evaluations.range_check1_selector8.is_some() {
            bits |= OptionalSelectorBits::RANGE_CHECK_1;
        }
        if column_evaluations.foreign_field_add_selector8.is_some() {
            bits |= OptionalSelectorBits::FOREIGN_FIELD_ADD;
        }
        if column_evaluations.foreign_field_mul_selector8.is_some() {
            bits |= OptionalSelectorBits::FOREIGN_FIELD_MUL;
        }
        if column_evaluations.xor_selector8.is_some() {
            bits |= OptionalSelectorBits::XOR;
        }
        if column_evaluations.rot_selector8.is_some() {
            bits |= OptionalSelectorBits::ROT;
        }
        bits
    };

    // Compute the lookup-presence bitmap up front so we can stamp it into
    // the header; the actual section payloads are emitted further below.
    let lookup_selectors_present = match lcs {
        None => 0,
        Some(lcs) => {
            let mut bits = 0u32;
            if lcs.table_ids8.is_some() {
                bits |= LookupSelectorBits::TABLE_IDS8;
            }
            if lcs.lookup_selectors.xor.is_some() {
                bits |= LookupSelectorBits::SELECTOR_XOR;
            }
            if lcs.lookup_selectors.lookup.is_some() {
                bits |= LookupSelectorBits::SELECTOR_LOOKUP;
            }
            if lcs.lookup_selectors.range_check.is_some() {
                bits |= LookupSelectorBits::SELECTOR_RANGE_CHECK;
            }
            if lcs.lookup_selectors.ffmul.is_some() {
                bits |= LookupSelectorBits::SELECTOR_FFMUL;
            }
            if lcs.runtime_selector.is_some() {
                bits |= LookupSelectorBits::RUNTIME_SELECTOR;
            }
            if lcs.runtime_tables.is_some() {
                bits |= LookupSelectorBits::RUNTIME_TABLES;
            }
            if lcs.runtime_table_offset.is_some() {
                bits |= LookupSelectorBits::RUNTIME_TABLE_OFFSET;
            }
            bits
        }
    };

    let header = ScalarHeader {
        public: cs.public as u32,
        prev_challenges: cs.prev_challenges as u32,
        zk_rows: cs.zk_rows,
        max_poly_size: index.max_poly_size as u64,
        disable_gates_checks: cs.disable_gates_checks,
        domain_d1_size: cs.domain.d1.size() as u64,
        feature_flags: pack_feature_flags(&cs.feature_flags),
        optional_selectors_present,
        lookup_selectors_present,
        has_verifier_index_digest: has_vkd,
        endo_limbs: field_to_limbs(&cs.endo),
        shift_limbs,
        verifier_index_digest_limbs: vkd_limbs,
    };

    // Assemble payload in an offset-agnostic way. The section table offsets
    // are computed after we know the number of sections (they all live in
    // the fixed region that precedes payload_base).
    let mut ctx = WriteContext::new();

    // sid as a field-slice section (elem_domain_size = sid length).
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::Sid as u32,
        cs.sid.len() as u32,
        &cs.sid,
    );

    // Pruned gates.
    let mut gates_bytes = Vec::with_capacity(cs.gates.len() * PRUNED_GATE_SIZE);
    for gate in cs.gates.iter() {
        write_pruned_gate(&mut gates_bytes, gate);
    }
    ctx.push_raw_section(SectionTag::Gates as u32, &gates_bytes);

    // Column evaluations: mandatory arrays.
    let d4_size = cs.domain.d4.size() as u32;
    let d8_size = cs.domain.d8.size() as u32;
    for (i, e) in column_evaluations.coefficients8.iter().enumerate() {
        ctx.push_field_section::<G::ScalarField>(coefficient_tag(i), d8_size, &e.evals);
    }
    for (i, e) in column_evaluations.permutation_coefficients8.iter().enumerate() {
        ctx.push_field_section::<G::ScalarField>(permutation_coefficient_tag(i), d8_size, &e.evals);
    }
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::GenericSelector4 as u32,
        d4_size,
        &column_evaluations.generic_selector4.evals,
    );
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::PoseidonSelector8 as u32,
        d8_size,
        &column_evaluations.poseidon_selector8.evals,
    );
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::CompleteAddSelector4 as u32,
        d4_size,
        &column_evaluations.complete_add_selector4.evals,
    );
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::MulSelector8 as u32,
        d8_size,
        &column_evaluations.mul_selector8.evals,
    );
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::EmulSelector8 as u32,
        d8_size,
        &column_evaluations.emul_selector8.evals,
    );
    ctx.push_field_section::<G::ScalarField>(
        SectionTag::EndomulScalarSelector8 as u32,
        d8_size,
        &column_evaluations.endomul_scalar_selector8.evals,
    );
    // Column evaluations: optional arrays.
    let push_optional = |ctx: &mut WriteContext, tag, opt: &Option<Evaluations<G::ScalarField, _>>| {
        if let Some(e) = opt {
            ctx.push_field_section::<G::ScalarField>(tag, d8_size, &e.evals);
        }
    };
    push_optional(
        &mut ctx,
        SectionTag::RangeCheck0Selector8 as u32,
        &column_evaluations.range_check0_selector8,
    );
    push_optional(
        &mut ctx,
        SectionTag::RangeCheck1Selector8 as u32,
        &column_evaluations.range_check1_selector8,
    );
    push_optional(
        &mut ctx,
        SectionTag::ForeignFieldAddSelector8 as u32,
        &column_evaluations.foreign_field_add_selector8,
    );
    push_optional(
        &mut ctx,
        SectionTag::ForeignFieldMulSelector8 as u32,
        &column_evaluations.foreign_field_mul_selector8,
    );
    push_optional(
        &mut ctx,
        SectionTag::XorSelector8 as u32,
        &column_evaluations.xor_selector8,
    );
    push_optional(
        &mut ctx,
        SectionTag::RotSelector8 as u32,
        &column_evaluations.rot_selector8,
    );

    // Lookup sections, only emitted when a LookupConstraintSystem was
    // materialised on the constraint system. The reader gates its lookup
    // reconstruction on the same `lookup_selectors_present` bitmap that
    // was just stamped into the header, so leaving any of these out when
    // lcs is None is correct — the reader will skip them.
    if let Some(lcs) = lcs {
        // lookup_table8: one section containing the concatenated inner
        // arrays, each d8-sized. The count of inner arrays is stored in
        // the section-table entry's `elem_domain_size`; the payload
        // itself is pure field data so it stays 32-byte aligned for
        // zero-copy slice construction at read time.
        {
            let n = lcs.lookup_table8.len() as u32;
            let inner_len = d8_size as usize * FIELD_ELEMENT_BYTES;
            let mut bytes = Vec::with_capacity((n as usize) * inner_len);
            for e in lcs.lookup_table8.iter() {
                write_field_slice(&mut bytes, &e.evals);
            }
            ctx.push_raw_section_with_elem_count(
                SectionTag::LookupTable8 as u32,
                n,
                &bytes,
            );
        }
        if let Some(e) = &lcs.table_ids8 {
            ctx.push_field_section::<G::ScalarField>(
                SectionTag::TableIds8 as u32,
                d8_size,
                &e.evals,
            );
        }
        push_optional(
            &mut ctx,
            SectionTag::LookupSelectorXor as u32,
            &lcs.lookup_selectors.xor,
        );
        push_optional(
            &mut ctx,
            SectionTag::LookupSelectorLookup as u32,
            &lcs.lookup_selectors.lookup,
        );
        push_optional(
            &mut ctx,
            SectionTag::LookupSelectorRangeCheck as u32,
            &lcs.lookup_selectors.range_check,
        );
        push_optional(
            &mut ctx,
            SectionTag::LookupSelectorFfmul as u32,
            &lcs.lookup_selectors.ffmul,
        );
        push_optional(
            &mut ctx,
            SectionTag::RuntimeSelector8 as u32,
            &lcs.runtime_selector,
        );
        if let Some(rts) = &lcs.runtime_tables {
            // Encoding: u32 count, then count × (id: i32 LE, len: u32 LE).
            // RuntimeTableSpec.len is usize in memory; we truncate to u32,
            // which is ample given real circuit sizes. The reader widens
            // it back to usize during reconstruction.
            let mut bytes = Vec::with_capacity(4 + rts.len() * 8);
            bytes.extend_from_slice(&(rts.len() as u32).to_le_bytes());
            for spec in rts {
                bytes.extend_from_slice(&(spec.id as i32).to_le_bytes());
                bytes.extend_from_slice(&(spec.len as u32).to_le_bytes());
            }
            ctx.push_raw_section(SectionTag::RuntimeTablesSpec as u32, &bytes);
        }
        if let Some(off) = lcs.runtime_table_offset {
            let bytes = (off as u64).to_le_bytes();
            ctx.push_raw_section(SectionTag::RuntimeTableOffset as u32, &bytes);
        }
    }

    // Once we know how many sections there are, we can compute the file
    // layout and patch section offsets to absolute file positions.
    let num_sections = ctx.sections.len();
    let payload_base = fixed_region_size(num_sections) as u64;
    for s in ctx.sections.iter_mut() {
        s.offset += payload_base;
    }
    ctx.payload_base = payload_base;

    // Build the file bytes: preamble + header + section table + pad to 32
    // + payload.
    let mut file = Vec::with_capacity(payload_base as usize + ctx.payload.len());
    write_preamble(&mut file, identifier, num_sections as u32)?;
    header.write(&mut file);
    for s in &ctx.sections {
        s.write(&mut file);
    }
    let fixed_region_end = PREAMBLE_SIZE
        + ScalarHeader::SERIALIZED_SIZE
        + num_sections * SectionEntry::SERIALIZED_SIZE;
    let pad = align_up(fixed_region_end) - fixed_region_end;
    file.extend(std::iter::repeat(0u8).take(pad));
    debug_assert_eq!(file.len() as u64, payload_base);
    file.extend_from_slice(&ctx.payload);

    // Atomic write: write to .tmp, fsync, rename into place.
    let tmp_path = {
        let mut p = path.to_path_buf();
        let name = p
            .file_name()
            .map(|f| f.to_owned())
            .unwrap_or_default();
        let mut tmp_name = name;
        tmp_name.push(".tmp");
        p.set_file_name(tmp_name);
        p
    };
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(&file)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Reads a cache file produced by [`write_cache`] and returns an
/// [`MmapProverIndex`]: a [`ProverIndex`]-compatible wrapper whose bulk
/// `Vec<F>` fields are backed by the mmap'd file rather than heap copies.
///
/// Reading is a single `mmap(2)` syscall; the prover reads field elements
/// directly from page-cache pages which the kernel can evict under
/// memory pressure and re-fault on demand. This is the "OS can evict
/// cached keys" behaviour the cache was designed for.
///
/// The returned `MmapProverIndex` [`Deref`]s to `&ProverIndex`, so existing
/// callers that pass `&ProverIndex<...>` into the prover continue to work
/// unchanged.
///
/// # Safety of the construction
///
/// This function constructs `Vec<F>` values via
/// `Vec::from_raw_parts(mmap_ptr, len, len)`, pointing directly into the
/// mmap. Those Vecs are bound by the lifetime of the mmap — which
/// [`MmapProverIndex`] guarantees by holding an `Arc<ReadOnlyMmap>`
/// alongside the wrapped index, and by wrapping the inner `ProverIndex`
/// in `ManuallyDrop` so `Vec::drop` can never run on them. See the
/// docstring on [`MmapProverIndex`] for the full invariant.
///
/// Identifier and ark-ff version must match the values the file was
/// produced with, otherwise a descriptive error is returned.
pub fn read_cache<const FULL_ROUNDS: usize, G, Srs>(
    identifier: &str,
    path: &Path,
    srs: Arc<Srs>,
) -> Result<MmapProverIndex<FULL_ROUNDS, G, Srs>, CacheError>
where
    G: KimchiCurve<FULL_ROUNDS>,
    Srs: SRS<G>,
    G::BaseField: ark_ff::PrimeField,
{
    assert_bigint_layout::<G::ScalarField>()?;

    let file = std::fs::File::open(path)?;
    // The mmap requires that the underlying file not be mutated by
    // external writers while the mapping is live. We document this
    // constraint in `key_cache.mli`. Concurrent writers use atomic rename,
    // which keeps the original inode alive for existing readers.
    let mmap = Arc::new(ReadOnlyMmap::map_file(&file)?);
    // SAFETY: we hold `mmap` in an Arc for the lifetime of the returned
    // MmapProverIndex; the `bytes` slice is therefore valid for as long as
    // the constructed `Vec<F>` views remain reachable. Since the returned
    // index lives inside `ManuallyDrop`, those Vecs never drop on their
    // own, so we never attempt to dealloc this mmap memory.
    let bytes: &[u8] = mmap.as_slice();

    // Preamble + identifier validation.
    let (preamble, rest) = read_preamble(bytes)?;
    if preamble.identifier != identifier {
        return Err(CacheError::IdentifierMismatch {
            found: preamble.identifier,
            expected: identifier.to_owned(),
        });
    }

    // ScalarHeader.
    let (header, mut rest) = ScalarHeader::read(rest)?;

    // Section table.
    let mut sections: std::collections::BTreeMap<u32, SectionEntry> = Default::default();
    for _ in 0..preamble.num_sections {
        let (entry, tail) = SectionEntry::read(rest)?;
        rest = tail;
        if entry.offset % SECTION_ALIGNMENT as u64 != 0 {
            return Err(CacheError::MisalignedSection {
                tag: entry.tag,
                offset: entry.offset,
            });
        }
        if sections.insert(entry.tag, entry).is_some() {
            return Err(CacheError::DuplicateSectionTag { tag: entry.tag });
        }
    }

    // Helper to slice a section payload out of the mapping.
    let section_bytes = |tag: u32| -> Result<&[u8], CacheError> {
        let entry = sections
            .get(&tag)
            .ok_or(CacheError::MissingSection { tag })?;
        let start = entry.offset as usize;
        let end = start
            .checked_add(entry.length as usize)
            .ok_or(CacheError::TruncatedFile)?;
        if end > bytes.len() {
            return Err(CacheError::TruncatedFile);
        }
        Ok(&bytes[start..end])
    };

    // Rebuild EvaluationDomains from d1_size.
    let d1_size = header.domain_d1_size as usize;
    let domain = EvaluationDomains::<G::ScalarField>::create(d1_size).map_err(|_| {
        CacheError::BadMagic { found: FILE_MAGIC } // surfaced as a format issue
    })?;
    let d4 = domain.d4;
    let d8 = domain.d8;

    // sid.
    let sid_entry = sections
        .get(&(SectionTag::Sid as u32))
        .ok_or(CacheError::MissingSection {
            tag: SectionTag::Sid as u32,
        })?;
    let sid_count = sid_entry.elem_domain_size as usize;
    let sid = unsafe {
        mmap_field_vec::<G::ScalarField>(
            section_bytes(SectionTag::Sid as u32)?,
            sid_count,
        )?
    };

    // Gates.
    let gates_bytes = section_bytes(SectionTag::Gates as u32)?;
    if gates_bytes.len() % PRUNED_GATE_SIZE != 0 {
        return Err(CacheError::PayloadNotFieldAligned {
            tag: SectionTag::Gates as u32,
            length: gates_bytes.len() as u64,
        });
    }
    let mut gates = Vec::with_capacity(gates_bytes.len() / PRUNED_GATE_SIZE);
    for chunk in gates_bytes.chunks_exact(PRUNED_GATE_SIZE) {
        gates.push(read_pruned_gate::<G::ScalarField>(chunk)?);
    }
    // Restore the single-element coeff stub `[F::one()]` on the first
    // `public` gates. `ProverIndex::verify` (run under `debug_assertions`)
    // reads `gate.coeffs.first()` to confirm each public row is tagged
    // correctly; without this stub, debug builds would fail that check
    // even though the column-evaluation selectors are valid.
    for gate in gates.iter_mut().take(header.public as usize) {
        gate.coeffs = vec![G::ScalarField::from(1u64)];
    }

    // Column evaluations. Each `Evaluations.evals` Vec points directly
    // into the mmap via `mmap_field_vec`; the `unsafe` block is sound so
    // long as the returned MmapProverIndex keeps the mmap alive and
    // wraps the ProverIndex in ManuallyDrop so Vec::drop never runs.
    let read_evals_d =
        |tag: u32, d: Radix2EvaluationDomain<G::ScalarField>| -> Result<Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>, CacheError> {
            let entry = sections
                .get(&tag)
                .ok_or(CacheError::MissingSection { tag })?;
            let count = entry.elem_domain_size as usize;
            let evals = unsafe {
                mmap_field_vec::<G::ScalarField>(section_bytes(tag)?, count)?
            };
            Ok(Evaluations::<G::ScalarField, _>::from_vec_and_domain(evals, d))
        };

    let mut coefficients8: Vec<Evaluations<G::ScalarField, _>> = Vec::with_capacity(COLUMNS);
    for i in 0..COLUMNS {
        coefficients8.push(read_evals_d(coefficient_tag(i), d8)?);
    }
    let coefficients8: [Evaluations<G::ScalarField, _>; COLUMNS] = coefficients8
        .try_into()
        .map_err(|_| CacheError::TruncatedFile)?;

    let mut permutation_coefficients8: Vec<Evaluations<G::ScalarField, _>> = Vec::with_capacity(PERMUTS);
    for i in 0..PERMUTS {
        permutation_coefficients8.push(read_evals_d(permutation_coefficient_tag(i), d8)?);
    }
    let permutation_coefficients8: [Evaluations<G::ScalarField, _>; PERMUTS] = permutation_coefficients8
        .try_into()
        .map_err(|_| CacheError::TruncatedFile)?;

    let generic_selector4 = read_evals_d(SectionTag::GenericSelector4 as u32, d4)?;
    let poseidon_selector8 = read_evals_d(SectionTag::PoseidonSelector8 as u32, d8)?;
    let complete_add_selector4 = read_evals_d(SectionTag::CompleteAddSelector4 as u32, d4)?;
    let mul_selector8 = read_evals_d(SectionTag::MulSelector8 as u32, d8)?;
    let emul_selector8 = read_evals_d(SectionTag::EmulSelector8 as u32, d8)?;
    let endomul_scalar_selector8 = read_evals_d(SectionTag::EndomulScalarSelector8 as u32, d8)?;

    let read_optional = |tag: u32, mask: u32| -> Result<Option<Evaluations<G::ScalarField, _>>, CacheError> {
        if header.optional_selectors_present & mask != 0 {
            Ok(Some(read_evals_d(tag, d8)?))
        } else {
            Ok(None)
        }
    };
    let range_check0_selector8 =
        read_optional(SectionTag::RangeCheck0Selector8 as u32, OptionalSelectorBits::RANGE_CHECK_0)?;
    let range_check1_selector8 =
        read_optional(SectionTag::RangeCheck1Selector8 as u32, OptionalSelectorBits::RANGE_CHECK_1)?;
    let foreign_field_add_selector8 = read_optional(
        SectionTag::ForeignFieldAddSelector8 as u32,
        OptionalSelectorBits::FOREIGN_FIELD_ADD,
    )?;
    let foreign_field_mul_selector8 = read_optional(
        SectionTag::ForeignFieldMulSelector8 as u32,
        OptionalSelectorBits::FOREIGN_FIELD_MUL,
    )?;
    let xor_selector8 = read_optional(SectionTag::XorSelector8 as u32, OptionalSelectorBits::XOR)?;
    let rot_selector8 = read_optional(SectionTag::RotSelector8 as u32, OptionalSelectorBits::ROT)?;

    let column_evaluations = ColumnEvaluations::<G::ScalarField> {
        permutation_coefficients8,
        coefficients8,
        generic_selector4,
        poseidon_selector8,
        complete_add_selector4,
        mul_selector8,
        emul_selector8,
        endomul_scalar_selector8,
        range_check0_selector8,
        range_check1_selector8,
        foreign_field_add_selector8,
        foreign_field_mul_selector8,
        xor_selector8,
        rot_selector8,
    };

    // Rebuild ConstraintSystem by going through its builder. The builder
    // recomputes sid and friends from the gates + public count, which is
    // exactly what we want.
    let feature_flags = unpack_feature_flags(header.feature_flags)?;
    let shift: [G::ScalarField; PERMUTS] = {
        let mut arr = [G::ScalarField::from(0u64); PERMUTS];
        for (i, limbs) in header.shift_limbs.iter().enumerate() {
            arr[i] = limbs_to_field::<G::ScalarField>(limbs);
        }
        arr
    };
    let endo = limbs_to_field::<G::ScalarField>(&header.endo_limbs);
    // We need a fully-populated ConstraintSystem. Rather than calling the
    // builder (which recomputes many fields we already have on disk), fill
    // it manually. This is equivalent to the `Deserialize` impl.
    let precomputations = Arc::new(LazyCache::new({
        let domain = domain;
        let zk_rows = header.zk_rows;
        move || {
            Arc::new(
                crate::circuits::domain_constant_evaluation::DomainConstantEvaluations::create(
                    domain, zk_rows,
                )
                .expect("domain constant evaluations"),
            )
        }
    }));
    // Reconstruct LookupConstraintSystem from sections 0x50..0x58 when the
    // presence bitmap indicates lookup data was written. The bitmap is the
    // same one we computed at write time (see `lookup_selectors_present`),
    // so an empty bitmap => no lookup sections and the read path short-
    // circuits to Ok(None) exactly as before.
    let lookup_constraint_system: Arc<
        LazyCache<Result<Option<LookupConstraintSystem<G::ScalarField>>, crate::circuits::lookup::index::LookupError>>,
    > = if header.lookup_selectors_present == 0
        && !sections.contains_key(&(SectionTag::LookupTable8 as u32))
    {
        Arc::new(LazyCache::new(|| Ok(None)))
    } else {
        // lookup_table8: count of inner arrays is carried in the section
        // entry's `elem_domain_size`; the payload is pure field data.
        // count == 0 is valid (empty lookup table).
        let lt_entry = sections
            .get(&(SectionTag::LookupTable8 as u32))
            .ok_or(CacheError::MissingSection {
                tag: SectionTag::LookupTable8 as u32,
            })?;
        let n = lt_entry.elem_domain_size as usize;
        let d8_size_usize = d8.size() as usize;
        let inner_bytes = d8_size_usize * FIELD_ELEMENT_BYTES;
        let lt_bytes = section_bytes(SectionTag::LookupTable8 as u32)?;
        let expected_total = n * inner_bytes;
        if lt_bytes.len() != expected_total {
            return Err(CacheError::SectionLengthMismatch {
                tag: SectionTag::LookupTable8 as u32,
                expected: expected_total as u64,
                found: lt_bytes.len() as u64,
            });
        }
        let mut lookup_table8: Vec<Evaluations<G::ScalarField, _>> = Vec::with_capacity(n);
        for i in 0..n {
            let start = i * inner_bytes;
            let end = start + inner_bytes;
            let evals = unsafe {
                mmap_field_vec::<G::ScalarField>(&lt_bytes[start..end], d8_size_usize)?
            };
            lookup_table8.push(Evaluations::from_vec_and_domain(evals, d8));
        }

        // Optional sections gated by LookupSelectorBits.
        let read_optional_evals = |tag: u32, bit: u32| -> Result<
            Option<Evaluations<G::ScalarField, Radix2EvaluationDomain<G::ScalarField>>>,
            CacheError,
        > {
            if header.lookup_selectors_present & bit != 0 {
                let entry = sections
                    .get(&tag)
                    .ok_or(CacheError::MissingSection { tag })?;
                let count = entry.elem_domain_size as usize;
                let evals = unsafe {
                    mmap_field_vec::<G::ScalarField>(section_bytes(tag)?, count)?
                };
                Ok(Some(Evaluations::from_vec_and_domain(evals, d8)))
            } else {
                Ok(None)
            }
        };
        let table_ids8 =
            read_optional_evals(SectionTag::TableIds8 as u32, LookupSelectorBits::TABLE_IDS8)?;
        let selector_xor = read_optional_evals(
            SectionTag::LookupSelectorXor as u32,
            LookupSelectorBits::SELECTOR_XOR,
        )?;
        let selector_lookup = read_optional_evals(
            SectionTag::LookupSelectorLookup as u32,
            LookupSelectorBits::SELECTOR_LOOKUP,
        )?;
        let selector_range_check = read_optional_evals(
            SectionTag::LookupSelectorRangeCheck as u32,
            LookupSelectorBits::SELECTOR_RANGE_CHECK,
        )?;
        let selector_ffmul = read_optional_evals(
            SectionTag::LookupSelectorFfmul as u32,
            LookupSelectorBits::SELECTOR_FFMUL,
        )?;
        let runtime_selector = read_optional_evals(
            SectionTag::RuntimeSelector8 as u32,
            LookupSelectorBits::RUNTIME_SELECTOR,
        )?;

        let runtime_tables: Option<Vec<RuntimeTableSpec>> =
            if header.lookup_selectors_present & LookupSelectorBits::RUNTIME_TABLES != 0 {
                let rt_bytes = section_bytes(SectionTag::RuntimeTablesSpec as u32)?;
                if rt_bytes.len() < 4 {
                    return Err(CacheError::TruncatedFile);
                }
                let mut count_buf = [0u8; 4];
                count_buf.copy_from_slice(&rt_bytes[..4]);
                let n = u32::from_le_bytes(count_buf) as usize;
                let expected = 4 + n * 8;
                if rt_bytes.len() != expected {
                    return Err(CacheError::SectionLengthMismatch {
                        tag: SectionTag::RuntimeTablesSpec as u32,
                        expected: expected as u64,
                        found: rt_bytes.len() as u64,
                    });
                }
                let mut out = Vec::with_capacity(n);
                for i in 0..n {
                    let base = 4 + i * 8;
                    let mut id_buf = [0u8; 4];
                    let mut len_buf = [0u8; 4];
                    id_buf.copy_from_slice(&rt_bytes[base..base + 4]);
                    len_buf.copy_from_slice(&rt_bytes[base + 4..base + 8]);
                    out.push(RuntimeTableSpec {
                        id: i32::from_le_bytes(id_buf),
                        len: u32::from_le_bytes(len_buf) as usize,
                    });
                }
                Some(out)
            } else {
                None
            };

        let runtime_table_offset: Option<usize> =
            if header.lookup_selectors_present & LookupSelectorBits::RUNTIME_TABLE_OFFSET != 0 {
                let off_bytes = section_bytes(SectionTag::RuntimeTableOffset as u32)?;
                if off_bytes.len() != 8 {
                    return Err(CacheError::SectionLengthMismatch {
                        tag: SectionTag::RuntimeTableOffset as u32,
                        expected: 8,
                        found: off_bytes.len() as u64,
                    });
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(off_bytes);
                Some(u64::from_le_bytes(buf) as usize)
            } else {
                None
            };

        // LookupInfo is a pure function of `feature_flags.lookup_features`;
        // we reconstruct it here rather than caching it separately.
        let lookup_info = LookupInfo::create(feature_flags.lookup_features);
        let lcs = LookupConstraintSystem {
            lookup_table: Vec::new(),
            lookup_table8,
            table_ids: None,
            table_ids8,
            lookup_selectors: LookupSelectors {
                xor: selector_xor,
                lookup: selector_lookup,
                range_check: selector_range_check,
                ffmul: selector_ffmul,
            },
            runtime_selector,
            runtime_tables,
            runtime_table_offset,
            configuration: LookupConfiguration::new(lookup_info),
        };
        Arc::new(LazyCache::new(move || Ok(Some(lcs))))
    };
    let cs = ConstraintSystem {
        public: header.public as usize,
        prev_challenges: header.prev_challenges as usize,
        domain,
        gates: Arc::new(gates),
        zk_rows: header.zk_rows,
        feature_flags,
        sid,
        shift,
        endo,
        lookup_constraint_system,
        precomputations,
        disable_gates_checks: header.disable_gates_checks,
    };

    // Re-derive linearization and powers_of_alpha.
    let (linearization, powers_of_alpha) = expr_linearization(Some(&cs.feature_flags), true);

    let verifier_index_digest = if header.has_verifier_index_digest {
        Some(limbs_to_field::<G::BaseField>(&header.verifier_index_digest_limbs))
    } else {
        None
    };

    let cs = Arc::new(cs);
    let column_evaluations_cache = Arc::new(LazyCache::new({
        let ce = column_evaluations;
        move || ce
    }));
    // Force evaluation so the LazyCache is populated (downstream code may
    // call `.get()` without checking status).
    column_evaluations_cache.get();

    let index = ProverIndex {
        cs,
        linearization,
        powers_of_alpha,
        srs,
        max_poly_size: header.max_poly_size as usize,
        column_evaluations: column_evaluations_cache,
        verifier_index: None,
        verifier_index_digest,
    };
    Ok(MmapProverIndex {
        index: core::mem::ManuallyDrop::new(index),
        _mmap: mmap,
    })
}
