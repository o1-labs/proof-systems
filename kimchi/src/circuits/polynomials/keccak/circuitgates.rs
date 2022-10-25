//~ The Keccak gadget is comprised of _ circuit gates (KeccakXor, .., and Zero)
//~
//~ Keccak works with 64-bit words. The state is represented using $5\times 5$ matrix
//~ of 64 bit words. Each compression step of Keccak consists of 24 rounds. Let us
//~ denote the state matrix with A (indexing elements as A[x,y]), from which we derive
//~further states as follows in each round. Each round then consists of the following 5 steps:
//~
//~ $$
//~ \begin{align}
//~ C[x] &= A[x,0] \oplus A[x,1] \oplus A[x,2] \oplus A[x,3] \oplus A[x,4] \\
//~ D[x] &= C[x-1] \oplus ROT(C[x+1],1) \\
//~ E[x,y] &= A[x,y]  \oplus D[x] \\
//~ B[y,2x+3y] &= ROT(E[x,y],\rho[x,y]) \\
//~ F[x,y] &= B[x,y] \oplus ((NOT B[x+1,y]) AND B[x+2,y]) \\
//~ Fp[0,0] &= F[0,0] \oplus RC
//~ \end{align}
//~ $$
//~
//~ FOR $0\leq x, y \leq 4$ and $\rho[x,y]$ is the rotation offset defined for Keccak.
//~
//~ ##### Design Approach:
//~
//~ The atomic operations are XOR, ROT, NOT, AND. In the sections below, we will describe
//~ the gates for these operations. Below are some common approaches followed in their design.
//~
//~ To fit within 15 wires, we first decompose each word into its lower and upper 32-bit
//~ components. A gate for an atomic operation works with those 32-bit components at a time.
//~
//~ Before we describe the specific gate design approaches, below are some constraints in the
//~ Kimchi framework that dictated those approaches.
//~ * only 4 lookups per row
//~ * only first 7 columns are available to the permutation polynomial
//~
//~ ```admonition::notice
//~  We could half the number of rows of the 64-bit XOR gadget by having lookups
//~  for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~ ```
//~
use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::constraints::{crumb, ExprOps},
    gate::GateType,
    polynomial::COLUMNS,
};
use ark_ff::PrimeField;

//~ ##### `KeccakXor` - XOR constraints for 32-bit words
//~
//~ Let `inp` be a 64-bit word. The constraint is: `in` $= 2^{32} \cdot$ `in_hi` $+$ `in_lo`.
//~ It takes 3 cells for values `in`, `in_hi`, `in_lo`. We have not yet placed them w.r.t.
//~ other rows of the Keccak computation; the only requirement is that all these cells be
//~ within the first 7 columns for permutation argument accessibility.
//
//~ * This circuit gate is used to constrain that `in1` xored with `in2` equals `out`.
//~ * This gate operates on the `Curr` row and the `Next` row.
//~
//~ It uses three different types of constraints
//~ * copy    - copy to another cell (32-bits)
//~ * plookup - xor-table plookup (4-bits)
//~
//~ The 4-bit crumbs are assumed to be laid out with `0` being the least significant crumb.
//~ Given values `in1`, `in2` and `out`, the layout looks like this:
//~
//~ First we consider a XOR gate that checks that a 32-bit word `out` is the XOR of `in1` and `in2`.
//~ This gate will use 2 rows, with a `Xor` row followed by a `Zero` row.
//~
//~ | Gates | `KeccakXor`      | `Zero`           |
//~ | ----- | ---------------- | ---------------- |
//~ | Rows  |           0      |           1      |
//~ | Cols  |                  |                  |
//~ |     0 | copy     `in1`   | copy     `out`   |
//~ |     1 |                  | copy     `in2`   |
//~ |     2 |                  |                  |
//~ |     3 | plookup0 `in2_0` | plookup4 `in2_4` |
//~ |     4 | plookup1 `in2_1` | plookup5 `in2_5` |
//~ |     5 | plookup2 `in2_2` | plookup6 `in2_6` |
//~ |     6 | plookup3 `in2_3` | plookup8 `in2_7` |
//~ |     7 | plookup0 `in1_0` | plookup4 `in1_4` |
//~ |     8 | plookup1 `in1_1` | plookup5 `in1_5` |
//~ |     9 | plookup2 `in1_2` | plookup6 `in1_6` |
//~ |    10 | plookup3 `in1_3` | plookup7 `in1_7` |
//~ |    11 | plookup0 `out_0` | plookup4 `out_4` |
//~ |    12 | plookup1 `out_1` | plookup5 `out_5` |
//~ |    13 | plookup2 `out_2` | plookup6 `out_6` |
//~ |    14 | plookup3 `out_3` | plookup7 `out_7` |
//~
//~ Now we apply this gate twice to obtain a XOR gadget for 64-bit words by halving:
//~
//~ Consider the following operations:
//~ * `out_lo` $=$ `in1_lo` $\oplus$ `in2_lo` and
//~ * `out_hi` $=$ `in1_hi` $\oplus$ `in2_hi`,
//~ where each element is 32 bits long.
//~
//~ | Gates | `KeccakXor` |   `Zero` | `KeccakXor` |   `Zero` |
//~ | ----- | ----------- | -------- | ----------- | -------- |
//~ | Rows  |          0  |       1  |          2  |        3 |
//~ | Cols  |             |          |             |          |
//~ |     0 |    `in1_lo` | `out_lo` |    `in1_hi` | `out_hi` |
//~ |     1 |             | `in2_lo` |             | `in2_hi` |
//~ |     2 |             |          |             |          |
//~ |     3 |     `in2_0` |  `in2_4` |     `in2_8` | `in2_12` |
//~ |     4 |     `in2_1` |  `in2_5` |     `in2_9` | `in2_13` |
//~ |     5 |     `in2_2` |  `in2_6` |    `in2_10` | `in2_14` |
//~ |     6 |     `in2_3` |  `in2_7` |    `in2_11` | `in2_15` |
//~ |     7 |     `in1_0` |  `in1_4` |     `in2_8` | `in2_12` |
//~ |     8 |     `in1_1` |  `in1_5` |     `in2_9` | `in2_13` |
//~ |     9 |     `in1_2` |  `in1_6` |    `in2_10` | `in2_14` |
//~ |    10 |     `in1_3` |  `in1_7` |    `in2_11` | `in2_15` |
//~ |    11 |     `out_0` |  `out_4` |     `in2_8` | `in2_12` |
//~ |    12 |     `out_1` |  `out_5` |     `in2_9` | `in2_13` |
//~ |    13 |     `out_2` |  `out_6` |    `in2_10` | `in2_14` |
//~ |    14 |     `out_3` |  `out_7` |    `in2_11` | `in2_15` |
//~
//~
//~ ##### Gate types:
//~
//~ Different rows are constrained using different CircuitGate types
//~
//~  | Row | `CircuitGate` | Purpose                        |
//~  | --- | ------------- | ------------------------------ |
//~  |   0 | `KeccakXor`   | Xor first 2 bytes of low  half |
//~  |   1 | `Zero`        | Xor last  2 bytes of low  half |
//~  |   2 | `KeccakXor`   | Xor first 2 bytes of high half |
//~  |   3 | `Zero`        | Xor last  2 bytes of high half |
//~
#[derive(Default)]
pub struct KeccakXor<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakXor<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakXor);
    const CONSTRAINTS: u32 = 3;

    // Constraints for KeccakXor
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `in1`, `in2` and `out`
    //   * The actual XOR is performed thanks to the plookups.
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let mut constraints = vec![];

        let out_sum = four_bit_sum(env, 14);
        let in1_sum = four_bit_sum(env, 10);
        let in2_sum = four_bit_sum(env, 6);

        // Check first input is well formed
        constraints.push(in1_sum - env.witness_curr(0));
        // Check second input is well formed
        constraints.push(in2_sum - env.witness_next(1));
        // Check output input is well formed
        constraints.push(out_sum - env.witness_next(0));

        constraints
    }
}

//~ ##### `KeccakRot` - Constraints for rotation of 64-bit words
//~
//~ * This circuit gate is used to constrain that a 64-bit word is rotated by r<64 bits to the "left".
//~ * The rotation is performed towards the most significant side (thus, the new LSB is fed with the old MSB).
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ The idea is to split the rotation operation into two parts:
//~ * Shift to the left
//~ * Add the excess bits to the right
//~
//~ We represent shifting with multiplication modulo 2^{64}. That is, for each word to be rotated, we provide in
//~ the witness a quotient and a remainder, similarly to `ForeignFieldMul` such that the following operation holds:
//~
//~ $$word \cdot 2^{rot} = quotient \cdot 2^{64} + remainder$$
//~
//~ Then, the remainder corresponds to the shifted word, and the quotient corresponds to the excess bits.
//~ Thus, in order to obtain the rotated word, we need to add the quotient and the remainder as follows:
//~
//~ $$rotated = shifted + excess$$
//~
//~ The input word is known to be of length 64 bits. All we need for soundness is check that the shifted and
//~ excess parts of the word have the correct size as well. That means, we need to range check that:
//~ $$
//~ \begin{aligned}
//~ excess &< 2^{rot}\\
//~ shifted &< 2^{64}
//~ \end{aligned}
//~ $$
//~ The latter can be obtained with a `RangeCheck0` gate setting the two most significant limbs to zero.
//~ The former is equivalent to the following check:
//~ $$excess - 2^{rot} + 2^{64} < 2^{64}$$
//~ which is doable with the constraints in a `RangeCheck0` gate. Since our current row within the `KeccakRot` gate
//~ is almost empty, we can use it to perform the range check within the same gate. Then, using the following layout
//~ and assuming that the gate has a coefficient storing the value $2^{rot}$,
//~
//~ | Gate   | `KeccakRot`         | `RangeCheck0`    |
//~ | ------ | ------------------- | ---------------- |
//~ | Column | `Curr`              | `Next`           |
//~ | ------ | ------------------- | ---------------- |
//~ |      0 | copy `word`         |`shifted`         |
//~ |      1 | copy `rotated`      | 0                |
//~ |      2 |      `excess`       | 0                |
//~ |      3 |      `bound_limb0`  | `shifted_limb0`  |
//~ |      4 |      `bound_limb1`  | `shifted_limb1`  |
//~ |      5 |      `bound_limb2`  | `shifted_limb2`  |
//~ |      6 |      `bound_limb3`  | `shifted_limb3`  |
//~ |      7 |      `bound_crumb0` | `shifted_crumb0` |
//~ |      8 |      `bound_crumb1` | `shifted_crumb1` |
//~ |      9 |      `bound_crumb2` | `shifted_crumb2` |
//~ |     10 |      `bound_crumb3` | `shifted_crumb3` |
//~ |     11 |      `bound_crumb4` | `shifted_crumb4` |
//~ |     12 |      `bound_crumb5` | `shifted_crumb5` |
//~ |     13 |      `bound_crumb6` | `shifted_crumb6` |
//~ |     14 |      `bound_crumb7` | `shifted_crumb7` |
//~
//~ In Keccak, rotations are performed over a 5x5 matrix state of w-bit words each cell. The values used
//~ to perform the rotation are fixed, public, and known in advance, according to the following table:
//~
//~ | y \ x |   0 |   1 |   2 |   3 |   4 |
//~ | ----- | --- | --- | --- | --- | --- |
//~ | 0     |   0 |   1 | 190 |  28 |  91 |
//~ | 1     |  36 | 300 |   6 |  55 | 276 |
//~ | 2     |   3 |  10 | 171 | 153 | 231 |
//~ | 3     | 105 |  45 |  15 |  21 | 136 |
//~ | 4     | 210 |  66 | 253 | 120 |  78 |
//~
//~ But since we are always using 64-bit words, we can have an equivalent table with these values modulo 64
//~ to avoid needing multiple passes of the rotation gate (a single step would cause overflows):
//~
//~ | y \ x |   0 |   1 |   2 |   3 |   4 |
//~ | ----- | --- | --- | --- | --- | --- |
//~ | 0     |   0 |   1 |  62 |  28 |  27 |
//~ | 1     |  36 |  44 |   6 |  55 |  20 |
//~ | 2     |   3 |  10 |  43 |  25 |  39 |
//~ | 3     |  41 |  45 |  15 |  21 |   8 |
//~ | 4     |  18 |   2 |  61 |  56 |  14 |
//~
//~ Since there is one value of the coordinates (x, y) where the rotation is 0 bits, we can skip that step in the
//~ gadget. This will save us one gate, and thus the whole 25-1=24 rotations will be performed in just 48 rows.
//~
#[derive(Default)]
pub struct KeccakRot<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakRot<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakRot);
    const CONSTRAINTS: u32 = 11;

    // Constraints for rotation of three 64-bit words by any three number of bits modulo 64
    // (stored in coefficient as a power-of-two form)
    //   * Operates on Curr row
    //   * Shifts the words by `rot` bits and then adds the excess to obtain the rotated word.
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // Check that the last 8 columns are 2-bit crumbs
        let mut constraints = (7..COLUMNS)
            .map(|i| crumb(&env.witness_curr(i)))
            .collect::<Vec<T>>();

        let two_to_64 = T::from(2u64).pow(64);

        let word = env.witness_curr(0);
        let rotated = env.witness_curr(1);
        let excess = env.witness_curr(2);
        let shifted = env.witness_next(0);
        let two_to_rot = env.coeff(0);

        // Obtains the following checks:
        // word * 2^{rot} = (excess * 2^64 + shifted)
        // rotated = shifted + excess
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
            power_of_2 *= T::from(4u64); // 2 bits
        }

        // Sum 12-bit limbs
        for i in (3..=6).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= 4096u64.into(); // 12 bits
        }

        // Check that bound = excess - 2^rot + 2^64 so as to prove that excess < 2^64
        constraints.push(bound - (excess - two_to_rot + two_to_64));

        constraints
    }
}

//~ ##### `KeccakWord` - 32-bit decomposition gate
//~
//~ This is a basic operation that is typically done for 64-bit initial state and
//~ intermediate values.
//~
//~ Let `inp` be a 64-bit word. The constraint is: `in` $= 2^32 \cdot$ `in_hi` $+$ `in_lo`.
//~ It takes 3 cells for values `in`, `in_hi`, `in_lo`. We have not yet placed them w.r.t
//~ other rows of the Keccak computation; the only requirement is that all these cells be
//~ within the first 7 columns for permutation equation accessibility.
//~
//~ * This circuit gate is used to constrain that two values of 64 bits are decomposed
//~   correctly in two halves of 32 bits. It will be used to constrain all inputs and
//~   intermediate values of the XOR gates.
//~ * This gate operates on the `Curr` row.
//~ * This is not a definitive gate. It may be integrated with other gates in the future.
//~
//~ It uses one type of constraint
//~ * copy    - copy to another cell (32-bits to the XOR gate, and 64-bits to the RangeCheck gate)
//~
//~ | Column |      `Curr`   |
//~ | ------ | ------------- |
//~ |      0 | copy `in1`    |
//~ |      1 | copy `in1_lo` |
//~ |      2 | copy `in1_hi` |
//~ |      3 | copy `in2`    |
//~ |      4 | copy `in2_lo` |
//~ |      5 | copy `in2_hi` |
//~ |      6 |               |
//~ |      7 |               |
//~ |      8 |               |
//~ |      9 |               |
//~ |     10 |               |
//~ |     11 |               |
//~ |     12 |               |
//~ |     13 |               |
//~ |     14 |               |
//~
//~ Note that these gates can be concatenated and the final output will still be satisfied
//~ despite having the positions for the second input to zero, because zero is a valid instance.

#[derive(Default)]
pub struct KeccakWord<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakWord<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakWord);
    const CONSTRAINTS: u32 = 2;

    // Constraints for Bits
    //   * Operates on Curr row
    //   * Constrain the decomposition of `in1` and `in2` in halves
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        vec![half(env, 0), half(env, 3)]
    }
}

/// Constrains the decomposition of an input of 64 bits located in position `idx`
/// into halves of 32 bits located in positions `idx+1` and `idx+2` in the `Curr` row.
fn half<F: PrimeField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>, idx: usize) -> T {
    let two = T::one() + T::one();
    let two_to_32 = two.pow(32);
    env.witness_curr(idx) - (env.witness_curr(idx + 2) * two_to_32 + env.witness_curr(idx + 1))
}

/// Computes the decomposition of a 32-bit word whose most significant 4-bit crumb
/// is located in the `max` column of `witness_next`. The layout is the following:
///
/// |        | max - 3 | max - 2 | max - 1 |     max |
/// | ------ | ------- | ------- | ------- | ------- |
/// | `Curr` |  crumb0 |  crumb1 |  crumb2 |  crumb3 |
/// | `Next` |  crumb4 |  crumb5 |  crumb6 |  crumb7 |
///
fn four_bit_sum<F: PrimeField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>, max: usize) -> T {
    let mut sum = T::zero();
    let two = T::from(2u64);
    let four_bit = two.pow(4);
    for i in (max - 3..=max).rev() {
        sum = four_bit.clone() * sum + env.witness_next(i);
    }
    for i in (max - 3..=max).rev() {
        sum = four_bit.clone() * sum + env.witness_curr(i);
    }
    sum
}
