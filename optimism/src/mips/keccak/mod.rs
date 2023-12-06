pub mod column;
pub mod constraints;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KTypeInstruction {
    // Either an Absorb or a Squeeze
    // Root: Whether the old state is the root state (only happens in the first absorb)
    // Pad: Whether the 10*1 padding rule is applied in this absrob sponge
    // usize: How many bytes are involved in the padding rule [0..136]
    SpongeSqueeze,
    SpongeAbsorb,
    SpongeAbsorbRoot,
    SpongeAbsorbPad(usize),
    SpongeAbsorbRootPad(usize),
    // Each of the 24 rounds involved in the permutation function
    Round(usize),
}

pub const DIM: usize = 5;
pub const QUARTERS: usize = 4;

fn grid_20(x: usize, q: usize) -> usize {
    q + QUARTERS * x
}

fn grid_80(i: usize, x: usize, q: usize) -> usize {
    q + QUARTERS * (x + DIM * i)
}

fn grid_100(y: usize, x: usize, q: usize) -> usize {
    q + QUARTERS * (x + DIM * y)
}

fn grid_400(i: usize, y: usize, x: usize, q: usize) -> usize {
    q + QUARTERS * (x + DIM * (y + DIM * i))
}

#[macro_export]
macro_rules! grid {
    (20, $v:expr) => {{
        |x: usize, q: usize| $v[q + QUARTERS * x].clone()
    }};
    (80, $v:expr) => {{
        |i: usize, x: usize, q: usize| $v[q + QUARTERS * (x + DIM * i)].clone()
    }};
    (100, $v:expr) => {{
        |y: usize, x: usize, q: usize| $v[q + QUARTERS * (x + DIM * y)].clone()
    }};
    (400, $v:expr) => {{
        |i: usize, y: usize, x: usize, q: usize| {
            $v[q + QUARTERS * (x + DIM * (y + DIM * i))].clone()
        }
    }};
}

#[macro_export]
macro_rules! from_quarters {
    ($quarters:ident, $x:ident) => {
        $quarters($x, 0)
            + T::two_pow(16) * $quarters($x, 1)
            + T::two_pow(32) * $quarters($x, 2)
            + T::two_pow(48) * $quarters($x, 3)
    };
    ($quarters:ident, $y:ident, $x:ident) => {
        $quarters($y, $x, 0)
            + T::two_pow(16) * $quarters($y, $x, 1)
            + T::two_pow(32) * $quarters($y, $x, 2)
            + T::two_pow(48) * $quarters($y, $x, 3)
    };
}

#[macro_export]
macro_rules! from_shifts {
    ($shifts:ident, $i:ident) => {
        $shifts($i)
            + T::two_pow(1) * $shifts(100 + $i)
            + T::two_pow(2) * $shifts(200 + $i)
            + T::two_pow(3) * $shifts(300 + $i)
    };
    ($shifts:ident, $x:ident, $q:ident) => {
        $shifts(0, $x, $q)
            + T::two_pow(1) * $shifts(1, $x, $q)
            + T::two_pow(2) * $shifts(2, $x, $q)
            + T::two_pow(3) * $shifts(3, $x, $q)
    };
    ($shifts:ident, $y:ident, $x:ident, $q:ident) => {
        $shifts(0, $y, $x, $q)
            + T::two_pow(1) * $shifts(1, $y, $x, $q)
            + T::two_pow(2) * $shifts(2, $y, $x, $q)
            + T::two_pow(3) * $shifts(3, $y, $x, $q)
    };
}

/// Creates the 5x5 table of rotation bits for Keccak modulo 64
/// | x \ y |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 | 36 |  3 | 41 | 18 |
/// | 1     |  1 | 44 | 10 | 45 |  2 |
/// | 2     | 62 |  6 | 43 | 15 | 61 |
/// | 3     | 28 | 55 | 25 | 21 | 56 |
/// | 4     | 27 | 20 | 39 |  8 | 14 |
/// Note that the order of the indexing is [y][x] to match the encoding of the witness algorithm
pub(crate) const OFF: [[u64; DIM]; DIM] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

pub const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
