//! Keccak gadget
use std::array;

use ark_ff::{PrimeField, SquareRootField};

use crate::circuits::{
    gate::{CircuitGate, Connect},
    polynomial::COLUMNS,
    polynomials::{
        generic::GenericGateSpec,
        rot::{self, RotMode},
    },
    wires::Wire,
};

/// Representation of the Keccak state of T type.
/// In our use case, T is a 64-bit unsigned integer,
/// or the corresponding field element.
#[derive(Debug, Clone)]
pub struct KeccakState<T> {
    pub state: [[T; MATRIX_DIM]; MATRIX_DIM],
}

impl<T: Clone> KeccakState<T> {
    /// Creates a new Keccak state with an input matrix of 5x5 elements
    /// Where the first index is the x coordinate and the second is the y coordinate
    pub fn new(state: [[T; MATRIX_DIM]; MATRIX_DIM]) -> Self {
        KeccakState { state }
    }

    /// Returns the element at the given coordinates (x, y)
    pub fn at(&self, x: usize, y: usize) -> T {
        self.state[x][y].clone()
    }
}

/// Length of the square matrix side of Keccak states
pub const MATRIX_DIM: usize = 5;
/// value `l` in Keccak, ranges from 0 to 6 (7 possible values)
pub const LENGTH: usize = 6;
/// width of the lane of the state, meaning the length of each word in bits
pub const WORD: usize = 2u32.pow(LENGTH as u32) as usize;
/// length of the state in bits, meaning the 5x5 matrix of words in bits
pub const STATE: usize = MATRIX_DIM.pow(2) * WORD;
/// number of rounds of the Keccak permutation function depending on the value `l`
pub const ROUNDS: usize = 12 + 2 * LENGTH;
/// Output length
pub const ETH_OUTPUT: usize = 256;
/// Capacity in Keccak256
pub const ETH_CAPACITY: usize = 512;
/// Bitrate in Keccak256
pub const ETH_BITRATE: usize = STATE - ETH_CAPACITY;

/// Creates the 5x5 table of rotation offset for Keccak modulo 64
/// | x \ y |  0 |  1 |  2 |  3 |  4 |
/// | ----- | -- | -- | -- | -- | -- |
/// | 0     |  0 | 36 |  3 | 41 | 18 |
/// | 1     |  1 | 44 | 10 | 45 |  2 |
/// | 2     | 62 |  6 | 43 | 15 | 61 |
/// | 3     | 28 | 55 | 25 | 21 | 56 |
/// | 4     | 27 | 20 | 39 |  8 | 14 |
pub const ROT_TAB: [[u32; MATRIX_DIM]; MATRIX_DIM] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Round constants for the 24 rounds of Keccak for the iota algorithm
pub const RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Creates Keccak gadget.
    /// Right now it only creates an initial generic gate with all zeros starting on `new_row` and then
    /// calls the Keccak rotation gadget
    pub fn create_keccak(new_row: usize) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the prefix of the output to be zero
        let mut gates = vec![CircuitGate::<F>::create_generic_gadget(
            Wire::for_row(new_row),
            GenericGateSpec::Pub,
            None,
        )];
        Self::create_keccak_rot(&mut gates, new_row + 1, new_row)
    }

    /// Creates Keccak rotation gates for the whole table (skipping the rotation by 0)
    pub fn create_keccak_rot(
        gates: &mut Vec<Self>,
        new_row: usize,
        zero_row: usize,
    ) -> (usize, Vec<Self>) {
        let mut rot_row = new_row;
        for row in ROT_TAB {
            for rot in row {
                // if rotation by 0 bits, no need to create a gate for it
                if rot == 0 {
                    continue;
                }
                let mut rot64_gates = Self::create_rot64(rot_row, rot);
                rot_row += rot64_gates.len();
                // Append them to the full gates vector
                gates.append(&mut rot64_gates);
                // Check that 2 most significant limbs of shifted are zero
                gates.connect_64bit(zero_row, rot_row - 1);
            }
        }
        (rot_row, gates.to_vec())
    }
}

/// Create a Keccak rotation (whole table)
/// Input: state (5x5) array of words to be rotated
pub fn create_witness_keccak_rot<F: PrimeField>(state: [[u64; 5]; 5]) -> [Vec<F>; COLUMNS] {
    // First generic gate with all zeros to constrain that the two most significant limbs of shifted output are zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);
    for (x, row) in ROT_TAB.iter().enumerate() {
        for (y, &rot) in row.iter().enumerate() {
            if rot == 0 {
                continue;
            }
            rot::extend_rot(&mut witness, state[x][y], rot, RotMode::Left);
        }
    }
    witness
}

// ///////////////////////////////////// //
// KECCAK HASH FUNCTION IMPLEMENTATION   //
// ///////////////////////////////////// //

// Performs the modulo operation, not remainder as in %
pub(crate) fn modulo(number: i32, modulo: i32) -> u64 {
    (((number % modulo) + modulo) % modulo).try_into().unwrap()
}

pub fn keccak_eth(message: &[u8]) -> Vec<u8> {
    keccak_hash(message, ETH_BITRATE, ETH_CAPACITY, ETH_OUTPUT)
}

pub fn sha3_256(message: &[u8]) -> Vec<u8> {
    keccak_hash(message, 1088, 512, 256)
}

pub fn sha3_512(message: &[u8]) -> Vec<u8> {
    keccak_hash(message, 576, 1024, 512)
}

/// Keccak hash function, does not accept messages whose length is not a multiple of 8 bits.
/// The message will be parsed as follows:
/// - the first byte of the message will be the least significant byte of the first word of the state (A[0][0])
/// - the 10*1 pad will take place after the message, until reaching the bit length BITRATE.
/// - then, {0} pad will take place to finish the 1600 bits of the state.
pub(crate) fn keccak_hash(
    message: &[u8],
    bitrate: usize,
    capacity: usize,
    output_length: usize,
) -> Vec<u8> {
    assert_eq!(
        capacity + bitrate,
        STATE,
        "Bitrate and capacity must sum up to 1600"
    );
    assert_eq!(bitrate % 8, 0, "Bitrate needs to be a multiple of 8");
    assert_eq!(
        output_length % 8,
        0,
        "Output length needs to be a multiple of 8"
    );
    let padded = pad(message, bitrate);
    let hash = keccak_sponge(padded, bitrate, capacity, output_length);
    hash
}

/// Pads a message M as:
/// M || pad[x](|M|)
/// Padding rule 10*1.
/// The padded message vector will start with the message vector
/// followed by the 10*1 rule to fulfill a length that is a multiple of bitrate.
pub(crate) fn pad(message: &[u8], bitrate: usize) -> Vec<u8> {
    // copy the message to the first part of the padded message
    let mut padded_message = message.clone().to_vec();
    // Add first 1 of the rule 10*1
    padded_message.push(0x01);
    while ((padded_message.len() * 8) % bitrate) != 0 {
        // keep adding 0s until the message (with a final 1) is a multiple of the bitrate
        padded_message.push(0x00);
    }
    // Include the final 1
    let last_byte = padded_message.len() - 1;
    padded_message[last_byte] |= 0x80;

    padded_message
}

// Keccak sponge function for 1600 bits of state width
// Need to split the message into blocks of 1088 bits
pub(crate) fn keccak_sponge(
    padded_message: Vec<u8>,
    bitrate: usize,
    capacity: usize,
    output_length: usize,
) -> Vec<u8> {
    assert_eq!(
        (padded_message.len() * 8) % bitrate,
        0,
        "Padded message needs to be a multiple of bitrate"
    );

    // absorb
    let root_state = [[0u64; MATRIX_DIM]; MATRIX_DIM];
    let mut state = root_state;
    // split into blocks of bitrate bits
    // for each block of bitrate bits in the padded message -> this is bitrate/8 bytes
    for block in padded_message.chunks(bitrate / 8) {
        let mut padded_block = block.to_vec();
        // pad the block with 0s to up to 1600 bits
        for _ in 0..(capacity / 8) {
            // (capacity / 8) zero bytes
            padded_block.push(0x00);
        }
        // padded with zeros each block until they are 1600 bit long
        assert_eq!(
            padded_block.len() * 8,
            STATE,
            "Padded block does not have 1600 bits"
        );
        let block_state = from_le_to_state(&padded_block);
        // xor the state with the padded block
        state = xor_state(state, block_state);
        // apply the permutation function to the xored state
        state = keccak_permutation(state);
    }

    // squeeze
    let mut output = from_state_to_le(state)[0..(bitrate / 8)].to_vec();
    while output.len() < output_length {
        // apply the permutation function to the state
        state = keccak_permutation(state);
        // append the output of the permutation function to the output
        output.append(&mut from_state_to_le(state)[0..(bitrate / 8)].to_vec());
    }
    // return the first 256 bits of the output
    let hashed = output[0..(output_length / 8)].to_vec().try_into().unwrap();
    hashed
}

// Performs the xor of two states of Keccak
pub(crate) fn xor_state(
    input1: [[u64; MATRIX_DIM]; MATRIX_DIM],
    input2: [[u64; MATRIX_DIM]; MATRIX_DIM],
) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let mut output = [[0u64; MATRIX_DIM]; MATRIX_DIM];
    for x in 0..MATRIX_DIM {
        for y in 0..MATRIX_DIM {
            output[x][y] = input1[x][y] ^ input2[x][y];
        }
    }
    output
}

/// Keccak permutation function for 1600 bits of state
pub fn keccak_permutation(
    state: [[u64; MATRIX_DIM]; MATRIX_DIM],
) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let mut state = state;
    // length could be anything between 0 and 6
    // In our use case, words have 64 bits, and thus length = 6
    // This implies that we must perform 24 rounds of the permutation function
    for round_number in 0..ROUNDS {
        state = round(state, round_number);
    }
    state
}

// The round applies the lambda function and then chi and iota
// It consists of the concatenation of the theta, rho, and pi algorithms.
// lambda = pi o rho o theta
// Thus:
// iota o chi o pi o rho o theta
pub(crate) fn round(
    state: [[u64; MATRIX_DIM]; MATRIX_DIM],
    round_number: usize,
) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let state_a = state;
    let state_e = theta(state_a);
    let state_b = pi_rho(state_e);
    let state_f = chi(state_b);
    let state_d = iota(state_f, RC[round_number]);
    state_d
}

// First algrithm in the compression step of Keccak for 64-bit words.
// C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4]
// D[x] = C[x-1] xor ROT(C[x+1], 1)
// E[x,y] = A[x,y] xor D[x]
// In the Keccak reference, it corresponds to the `theta` algorithm.
// We use the first index of the state array as the x coordinate and the second index as the y coordinate.
pub(crate) fn theta(state: [[u64; MATRIX_DIM]; MATRIX_DIM]) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let state_a = state;
    let mut state_c = [0u64; MATRIX_DIM];
    let mut state_d = [0u64; MATRIX_DIM];
    let mut state_e = [[0u64; MATRIX_DIM]; MATRIX_DIM];
    // for all x in {0..4}: C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4]
    for x in 0..MATRIX_DIM {
        state_c[x] = state_a[x][0] ^ state_a[x][1] ^ state_a[x][2] ^ state_a[x][3] ^ state_a[x][4];
    }
    // for all x in {0..4}: D[x] = C[x-1] xor ROT(C[x+1], 1)
    for x in 0..MATRIX_DIM {
        let x_minus_one = modulo((x as i32) - 1, MATRIX_DIM as i32) as usize;
        let x_plus_one = modulo((x as i32) + 1, MATRIX_DIM as i32) as usize;
        state_d[x as usize] = state_c[x_minus_one] ^ (state_c[x_plus_one]).rotate_left(1);
        // for all y in {0..4}: E[x,y] = A[x,y] xor D[x]
        for y in 0..MATRIX_DIM {
            state_e[x][y] = state_a[x][y] ^ state_d[x];
        }
    }
    state_e
}

// Second and third steps in the compression step of Keccak for 64-bit words.
// B[y,2x+3y] = ROT(E[x,y], r[x,y])
// which is equivalent to the `rho` algorithm followed by the `pi` algorithm in the Keccak reference as follows:
// rho:
// A[0,0] = a[0,0]
// | x |  =  | 1 |
// | y |  =  | 0 |
// for t = 0 to 23 do
//   A[x,y] = ROT(a[x,y], (t+1)(t+2)/2 mod 64)))
//   | x |  =  | 0  1 |   | x |
//   |   |  =  |      | * |   |
//   | y |  =  | 2  3 |   | y |
// end for
// pi:
// for x = 0 to 4 do
//   for y = 0 to 4 do
//     | X |  =  | 0  1 |   | x |
//     |   |  =  |      | * |   |
//     | Y |  =  | 2  3 |   | y |
//     A[X,Y] = a[x,y]
//   end for
// end for
// We use the first index of the state array as the x coordinate and the second index as the y coordinate.
pub(crate) fn pi_rho(state: [[u64; MATRIX_DIM]; MATRIX_DIM]) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let state_e = state;
    let mut state_b = [[0u64; MATRIX_DIM]; MATRIX_DIM];
    // for all x in {0..4} and y in {0..4}: B[y, 2x+3y] = ROT(E[x,y], r[x,y])
    for x in 0..MATRIX_DIM {
        for y in 0..MATRIX_DIM {
            let two_x_plus_three_y = modulo((2 * x + 3 * y) as i32, MATRIX_DIM as i32) as usize;
            state_b[y][two_x_plus_three_y] = state_e[x][y].rotate_left(ROT_TAB[x][y]);
        }
    }
    state_b
}

// Fourth step of the compression function of Keccak for 64-bit words.
// F[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y])
// It corresponds to the chi algorithm in the Keccak reference.
// for y = 0 to 4 do
//   for x = 0 to 4 do
//     A[x,y] = a[x,y] xor ((not a[x+1,y]) and a[x+2,y])
//   end for
// end for
pub(crate) fn chi(state: [[u64; MATRIX_DIM]; MATRIX_DIM]) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let state_b = state;
    let mut state_f = [[0u64; MATRIX_DIM]; MATRIX_DIM];
    // for all x in {0..4} and y in {0..4}: F[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y])
    for y in 0..MATRIX_DIM {
        for x in 0..MATRIX_DIM {
            let x_plus_one = modulo((x as i32) + 1, MATRIX_DIM as i32) as usize;
            let x_plus_two = modulo((x as i32) + 2, MATRIX_DIM as i32) as usize;
            state_f[x][y] = state_b[x][y] ^ ((!state_b[x_plus_one][y]) & state_b[x_plus_two][y]);
        }
    }
    state_f
}

// Fifth step of the permutation function of Keccak for 64-bit words.
// It takes the word located at the position (0,0) of the state and XORs it with the round constant.
pub(crate) fn iota(
    state: [[u64; MATRIX_DIM]; MATRIX_DIM],
    round_constant: u64,
) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    let mut state_g = state;
    state_g[0][0] ^= round_constant;
    state_g
}

// Transforms a vector of bytes in little endian  into a state of 64-bit words
// Assuming that the first 5 words correspond to the x=0 row.
// The first byte of the vector corresponds to the least significant byte of the first word of the state (x=0, y=0).
pub(crate) fn from_le_to_state(block: &[u8]) -> [[u64; MATRIX_DIM]; MATRIX_DIM] {
    assert_eq!(block.len() * 8, 1600, "The block must have 1600 bits");
    let mut state = [[0u64; MATRIX_DIM]; MATRIX_DIM];
    for x in 0..MATRIX_DIM {
        for y in 0..MATRIX_DIM {
            // each word has 8 bytes -> 64 bits
            for z in 0..(WORD / 8) {
                let index = 8 * (MATRIX_DIM * x + y) + z;
                state[x][y] |= (block[index] as u64) << 8 * z;
            }
        }
    }
    state
}

// Transforms a state of 64-bit words into a vector of bytes in little endian
pub(crate) fn from_state_to_le(state: [[u64; MATRIX_DIM]; MATRIX_DIM]) -> Vec<u8> {
    let mut block = vec![];
    for x in 0..MATRIX_DIM {
        for y in 0..MATRIX_DIM {
            for z in 0..(WORD / 8) {
                block.push(((state[x][y] >> 8 * z) & 0xFF) as u8);
            }
        }
    }
    block
}
