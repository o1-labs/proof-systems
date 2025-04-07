//~ Rotation of a 64-bit word by a known offset

use super::range_check::witness::range_check_0_row;
use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        berkeley_columns::BerkeleyChallengeTerm,
        expr::{
            constraints::{crumb, ExprOps},
            Cache,
        },
        gate::{CircuitGate, Connect, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        polynomial::COLUMNS,
        wires::Wire,
        witness::{self, VariableBitsCell, VariableCell, Variables, WitnessCell},
    },
    variable_map,
};
use ark_ff::PrimeField;
use core::{array, marker::PhantomData};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RotMode {
    Left,
    Right,
}

impl<F: PrimeField> CircuitGate<F> {
    /// Creates a Rot64 gadget to rotate a word
    /// It will need:
    /// - 1 Generic gate to constrain to zero the top 2 limbs of the shifted and
    ///   excess witness of the rotation
    ///
    /// It has:
    /// - 1 Rot64 gate to rotate the word
    /// - 1 RangeCheck0 to constrain the size of the shifted witness of the
    ///   rotation
    /// - 1 RangeCheck0 to constrain the size of the excess witness of the
    ///   rotation
    ///
    /// Assumes:
    /// - the witness word is 64-bits, otherwise, will need to append a new RangeCheck0 for the word
    pub fn create_rot64(new_row: usize, rot: u32) -> Vec<Self> {
        vec![
            CircuitGate {
                typ: GateType::Rot64,
                wires: Wire::for_row(new_row),
                coeffs: vec![F::two_pow(rot as u64)],
            },
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: Wire::for_row(new_row + 1),
                coeffs: vec![F::zero()],
            },
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: Wire::for_row(new_row + 2),
                coeffs: vec![F::zero()],
            },
        ]
    }

    /// Extend one rotation
    /// Right now it only creates a Generic gate followed by the Rot64 gates
    /// It allows to configure left or right rotation.
    ///
    /// Input:
    /// - gates : the full circuit
    /// - rot : the rotation offset
    /// - side : the rotation side
    /// - zero_row : the row of the Generic gate to constrain the 64-bit check of shifted word
    ///
    /// Warning:
    /// - witness word should come from the copy of another cell so it is intrinsic that it is 64-bits length,
    /// - same with rotated word
    pub fn extend_rot(gates: &mut Vec<Self>, rot: u32, side: RotMode, zero_row: usize) -> usize {
        let (new_row, mut rot_gates) = Self::create_rot(gates.len(), rot, side);
        gates.append(&mut rot_gates);
        // Check that 2 most significant limbs of shifted and excess are zero
        gates.connect_64bit(zero_row, new_row - 2);
        gates.connect_64bit(zero_row, new_row - 1);
        // Connect excess with the Rot64 gate
        gates.connect_cell_pair((new_row - 3, 2), (new_row - 1, 0));

        gates.len()
    }

    /// Create one rotation
    /// Right now it only creates a Generic gate followed by the Rot64 gates
    /// It allows to configure left or right rotation.
    ///
    /// Input:
    /// - rot : the rotation offset
    /// - side : the rotation side
    ///
    /// Warning:
    /// - Word should come from the copy of another cell so it is intrinsic that it is 64-bits length,
    /// - same with rotated word
    /// - need to check that the 2 most significant limbs of shifted are zero
    pub fn create_rot(new_row: usize, rot: u32, side: RotMode) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the output to be zero
        let rot_gates = if side == RotMode::Left {
            Self::create_rot64(new_row, rot)
        } else {
            Self::create_rot64(new_row, 64 - rot)
        };

        (new_row + rot_gates.len(), rot_gates)
    }
}

/// Get the rot lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::RangeCheck)
}

//~ `Rot64` onstrains known-length rotation of 64-bit words:
//~
//~ * This circuit gate is used to constrain that a 64-bit word is rotated by $r < 64$ bits to the "left".
//~ * The rotation is performed towards the most significant side (thus, the new LSB is fed with the old MSB).
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ The idea is to split the rotation operation into two parts:
//~
//~ * Shift to the left
//~ * Add the excess bits to the right
//~
//~ We represent shifting with multiplication modulo $2^{64}$. That is, for each word to be rotated, we provide in
//~ the witness a quotient and a remainder, similarly to `ForeignFieldMul` such that the following operation holds:
//~
//~ $$word \cdot 2^{rot} = quotient \cdot 2^{64} + remainder$$
//~
//~ Then, the remainder corresponds to the shifted word, and the quotient corresponds to the excess bits.
//~
//~ $$word \cdot 2^{rot} = excess \cdot 2^{64} + shifted$$
//~
//~ Thus, in order to obtain the rotated word, we need to add the quotient and the remainder as follows:
//~
//~ $$rotated = shifted + excess$$
//~
//~ The input word is known to be of length 64 bits. All we need for soundness is check that the shifted and
//~ excess parts of the word have the correct size as well. That means, we need to range check that:
//~
//~ $$
//~ \begin{aligned}
//~ excess &< 2^{rot}\\
//~ shifted &< 2^{64}
//~ \end{aligned}
//~ $$
//~
//~ The latter can be obtained with a `RangeCheck0` gate setting the two most significant limbs to zero.
//~ The former is equivalent to the following check:
//~
//~ $$bound = excess - 2^{rot} + 2^{64} < 2^{64}$$
//~
//~ which is doable with the constraints in a `RangeCheck0` gate. Since our current row within the `Rot64` gate
//~ is almost empty, we can use it to perform the range check within the same gate. Then, using the following layout
//~ and assuming that the gate has a coefficient storing the value $2^{rot}$, which is publicly known
//~
//~ | Gate   | `Rot64`             | `RangeCheck0` gadgets (designer's duty)                   |
//~ | ------ | ------------------- | --------------------------------------------------------- |
//~ | Column | `Curr`              | `Next`           | `Next` + 1      | `Next`+ 2, if needed |
//~ | ------ | ------------------- | ---------------- | --------------- | -------------------- |
//~ |      0 | copy `word`         |`shifted`         |   copy `excess` |    copy      `word`  |
//~ |      1 | copy `rotated`      | 0                |              0  |                  0   |
//~ |      2 |      `excess`       | 0                |              0  |                  0   |
//~ |      3 |      `bound_limb0`  | `shifted_limb0`  |  `excess_limb0` |        `word_limb0`  |
//~ |      4 |      `bound_limb1`  | `shifted_limb1`  |  `excess_limb1` |        `word_limb1`  |
//~ |      5 |      `bound_limb2`  | `shifted_limb2`  |  `excess_limb2` |        `word_limb2`  |
//~ |      6 |      `bound_limb3`  | `shifted_limb3`  |  `excess_limb3` |        `word_limb3`  |
//~ |      7 |      `bound_crumb0` | `shifted_crumb0` | `excess_crumb0` |       `word_crumb0`  |
//~ |      8 |      `bound_crumb1` | `shifted_crumb1` | `excess_crumb1` |       `word_crumb1`  |
//~ |      9 |      `bound_crumb2` | `shifted_crumb2` | `excess_crumb2` |       `word_crumb2`  |
//~ |     10 |      `bound_crumb3` | `shifted_crumb3` | `excess_crumb3` |       `word_crumb3`  |
//~ |     11 |      `bound_crumb4` | `shifted_crumb4` | `excess_crumb4` |       `word_crumb4`  |
//~ |     12 |      `bound_crumb5` | `shifted_crumb5` | `excess_crumb5` |       `word_crumb5`  |
//~ |     13 |      `bound_crumb6` | `shifted_crumb6` | `excess_crumb6` |       `word_crumb6`  |
//~ |     14 |      `bound_crumb7` | `shifted_crumb7` | `excess_crumb7` |       `word_crumb7`  |
//~
//~ In Keccak, rotations are performed over a 5x5 matrix state of w-bit words each cell. The values used
//~ to perform the rotation are fixed, public, and known in advance, according to the following table,
//~ depending on the coordinate of each cell within the 5x5 matrix state:
//~
//~ | y \ x |   0 |   1 |   2 |   3 |   4 |
//~ | ----- | --- | --- | --- | --- | --- |
//~ | 0     |   0 |  36 |   3 | 105 | 210 |
//~ | 1     |   1 | 300 |  10 |  45 |  66 |
//~ | 2     | 190 |   6 | 171 |  15 | 253 |
//~ | 3     |  28 |  55 | 153 |  21 | 120 |
//~ | 4     |  91 | 276 | 231 | 136 |  78 |
//~
//~ But since we will always be using 64-bit words in our Keccak usecase ($w = 64$), we can have an equivalent
//~ table with these values modulo 64 to avoid needing multiple passes of the rotation gate (a single step would
//~ cause overflows otherwise):
//~
//~ | y \ x |   0 |   1 |   2 |   3 |   4 |
//~ | ----- | --- | --- | --- | --- | --- |
//~ | 0     |   0 |  36 |   3 |  41 |  18 |
//~ | 1     |   1 |  44 |  10 |  45 |   2 |
//~ | 2     |  62 |   6 |  43 |  15 |  61 |
//~ | 3     |  28 |  55 |  25 |  21 |  56 |
//~ | 4     |  27 |  20 |  39 |   8 |  14 |
//~
//~ Since there is one value of the coordinates (x, y) where the rotation is 0 bits, we can skip that step in the
//~ gadget. This will save us one gate, and thus the whole 25-1=24 rotations will be performed in just 48 rows.
//~
#[derive(Default)]
pub struct Rot64<F>(PhantomData<F>);

impl<F> Argument<F> for Rot64<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Rot64);
    const CONSTRAINTS: u32 = 11;

    // Constraints for rotation of three 64-bit words by any three number of bits modulo 64
    // (stored in coefficient as a power-of-two form)
    //   * Operates on Curr row
    //   * Shifts the words by `rot` bits and then adds the excess to obtain the rotated word.
    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        _cache: &mut Cache,
    ) -> Vec<T> {
        // Check that the last 8 columns are 2-bit crumbs
        // C1..C8: x * (x - 1) * (x - 2) * (x - 3) = 0
        let mut constraints = (7..COLUMNS)
            .map(|i| crumb(&env.witness_curr(i)))
            .collect::<Vec<T>>();

        // NOTE:
        // If we ever want to make this gate more generic, the power of two for the length
        // could be a coefficient of the gate instead of a fixed value in the constraints.
        let two_to_64 = T::two_pow(64);

        let word = env.witness_curr(0);
        let rotated = env.witness_curr(1);
        let excess = env.witness_curr(2);
        let shifted = env.witness_next(0);
        let two_to_rot = env.coeff(0);

        // Obtains the following checks:
        // C9: word * 2^{rot} = (excess * 2^64 + shifted)
        // C10: rotated = shifted + excess
        constraints.push(
            word * two_to_rot.clone() - (excess.clone() * two_to_64.clone() + shifted.clone()),
        );
        constraints.push(rotated - (shifted + excess.clone()));

        // Compute the bound from the crumbs and limbs
        let mut power_of_2 = T::one();
        let mut bound = T::zero();

        // Sum 2-bit limbs
        for i in (7..COLUMNS).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= T::two_pow(2); // 2 bits
        }

        // Sum 12-bit limbs
        for i in (3..=6).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= T::two_pow(12); // 12 bits
        }

        // Check that excess < 2^rot by checking that bound < 2^64
        // Check RFC of Keccak for more details on the proof of this
        // C11:bound = excess - 2^rot + 2^64
        constraints.push(bound - (excess - two_to_rot + two_to_64));

        constraints
    }
}

// ROTATION WITNESS COMPUTATION

fn layout_rot64<F: PrimeField>(curr_row: usize) -> [Vec<Box<dyn WitnessCell<F>>>; 3] {
    [
        rot_row(),
        range_check_0_row("shifted", curr_row + 1),
        range_check_0_row("excess", curr_row + 2),
    ]
}

fn rot_row<F: PrimeField>() -> Vec<Box<dyn WitnessCell<F>>> {
    vec![
        VariableCell::create("word"),
        VariableCell::create("rotated"),
        VariableCell::create("excess"),
        /* 12-bit plookups */
        VariableBitsCell::create("bound", 52, Some(64)),
        VariableBitsCell::create("bound", 40, Some(52)),
        VariableBitsCell::create("bound", 28, Some(40)),
        VariableBitsCell::create("bound", 16, Some(28)),
        /* 2-bit crumbs */
        VariableBitsCell::create("bound", 14, Some(16)),
        VariableBitsCell::create("bound", 12, Some(14)),
        VariableBitsCell::create("bound", 10, Some(12)),
        VariableBitsCell::create("bound", 8, Some(10)),
        VariableBitsCell::create("bound", 6, Some(8)),
        VariableBitsCell::create("bound", 4, Some(6)),
        VariableBitsCell::create("bound", 2, Some(4)),
        VariableBitsCell::create("bound", 0, Some(2)),
    ]
}

fn init_rot64<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    curr_row: usize,
    word: F,
    rotated: F,
    excess: F,
    shifted: F,
    bound: F,
) {
    let rot_rows = layout_rot64(curr_row);
    witness::init(
        witness,
        curr_row,
        &rot_rows,
        &variable_map!["word" => word, "rotated" => rotated, "excess" => excess, "shifted" => shifted, "bound" => excess+bound],
    );
}

/// Extends the rot rows to the full witness
/// Input
/// - witness: full witness of the circuit
/// - word: 64-bit word to be rotated
/// - rot:  rotation offset
/// - side: side of the rotation, either left or right
///
/// Warning:
/// - don't forget to include a public input row with zero value
pub fn extend_rot<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    word: u64,
    rot: u32,
    side: RotMode,
) {
    assert!(rot <= 64, "Rotation value must be less or equal than 64");

    let rot = if side == RotMode::Right {
        64 - rot
    } else {
        rot
    };
    // Split word into shifted and excess parts to compute the witnesses for rotation as follows
    //          <   64     >  bits
    // word   = [---|------]
    //          <rot>         bits
    // excess = [---]
    // shifted      [------] * 2^rot
    // rot    = [------|000]
    //        +        [---] excess
    let shifted = (word as u128) * 2u128.pow(rot) % 2u128.pow(64);
    let excess = (word as u128) / 2u128.pow(64 - rot);
    let rotated = shifted + excess;
    // Value for the added value for the bound
    // Right input of the "FFAdd" for the bound equation
    let bound = 2u128.pow(64) - 2u128.pow(rot);

    let rot_row = witness[0].len();
    let rot_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 3]);
    for col in 0..COLUMNS {
        witness[col].extend(rot_witness[col].iter());
    }
    init_rot64(
        witness,
        rot_row,
        word.into(),
        rotated.into(),
        excess.into(),
        shifted.into(),
        bound.into(),
    );
}
