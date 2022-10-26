//~ The Keccak gadget is comprised of 3 circuit gates (Xor16, Rot64, and Zero)
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
use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::constraints::{crumb, ExprOps},
    gate::GateType,
    polynomial::COLUMNS,
};
use ark_ff::PrimeField;

//~ ##### `Xor16` - Chainable XOR constraints for words of multiples of 16 bits.
//~
//~ * This circuit gate is used to constrain that `in1` xored with `in2` equals `out`
//~ * The length of `in1`, `in2` and `out` must be the same and a multiple of 16bits.
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ It uses three different types of constraints
//~ * copy          - copy to another cell (32-bits)
//~ * plookup       - xor-table plookup (4-bits)
//~ * decomposition - the constraints inside the gate
//~
//~ The 4-bit crumbs are assumed to be laid out with `0` column being the least significant crumb.
//~ Given values `in1`, `in2` and `out`, the layout looks like this:
//~
//~ | Column |          `Curr`  |          `Next`  |
//~ | ------ | ---------------- | ---------------- |
//~ |      0 | copy     `in1`   | copy     `in1'`  |
//~ |      1 | copy     `in2`   | copy     `in2'`  |
//~ |      2 | copy     `out`   | copy     `out'`  |
//~ |      3 | plookup0 `in1_0` |                  |
//~ |      4 | plookup1 `in1_1` |                  |
//~ |      5 | plookup2 `in1_2` |                  |
//~ |      6 | plookup3 `in1_3` |                  |
//~ |      7 | plookup0 `in2_0` |                  |
//~ |      8 | plookup1 `in2_1` |                  |
//~ |      9 | plookup2 `in2_2` |                  |
//~ |     10 | plookup3 `in2_3` |                  |
//~ |     11 | plookup0 `out_0` |                  |
//~ |     12 | plookup1 `out_1` |                  |
//~ |     13 | plookup2 `out_2` |                  |
//~ |     14 | plookup3 `out_3` |                  |
//~
//~ One single gate with next values of `in1'`, `in2'` and `out'` being zero can be used to check
//~ that the original `in1`, `in2` and `out` had 16-bits. We can chain this gate 4 times as follows
//~ to obtain a gadget for 64-bit words XOR:
//~
//~  | Row | `CircuitGate` | Purpose                                    |
//~  | --- | ------------- | ------------------------------------------ |
//~  |   0 | `Xor16`       | Xor 2 least significant bytes of the words |
//~  |   1 | `Xor16`       | Xor next 2 bytes of the words              |
//~  |   2 | `Xor16`       | Xor next 2 bytes of the words              |
//~  |   3 | `Xor16`       | Xor 2 most significant bytes of the words  |
//~  |   4 | `Zero`        | Zero values, can be reused as generic gate |
//~
//~ ```admonition::notice
//~  We could half the number of rows of the 64-bit XOR gadget by having lookups
//~  for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~  Rough computations show that if we run 8 or more Keccaks in one circuit we should
//~  use the 8-bit XOR table.
//~ ```
#[derive(Default)]
pub struct Xor16<F>(PhantomData<F>);

impl<F> Argument<F> for Xor16<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Xor16);
    const CONSTRAINTS: u32 = 3;

    // Constraints for Xor16
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `in1`, `in2` and `out` of multiples of 16 bits
    //   * The actual XOR is performed thanks to the plookups of 4-bit XORs.
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // Returns the constraints:
        // in1 = in1_0 + in1_1 * 2^4 + in1_2 * 2^8 + in1_3 * 2^12 + next_in1 * 2^16
        // in2 = in2_0 + in2_1 * 2^4 + in2_2 * 2^8 + in2_3 * 2^12 + next_in2 * 2^16
        // out = out_0 + out_1 * 2^4 + out_2 * 2^8 + out_3 * 2^12 + next_out * 2^16
        (0..3)
            .map(|i| {
                env.witness_curr(i)
                    - quarter_sum(env, 3 + i)
                    - T::from(2u64).pow(16) * env.witness_next(i)
            })
            .collect::<Vec<T>>()
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

/// Computes the decomposition of a 16-bit quarter-word whose least significant 4-bit crumb
/// is located in the `lsb` column of `witness_curr` as:
/// sum = crumb0 + crumb1 * 2^4 + crumb2 * 2^8 + crumb3 * 2^12
///
/// The layout is the following:
///
/// |        | lsb     | lsb + 3 | lsb + 6 | lsb + 9 |
/// | ------ | ------- | ------- | ------- | ------- |
/// | `Curr` |  crumb0 |  crumb1 |  crumb2 |  crumb3 |
///
fn quarter_sum<F: PrimeField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>, lsb: usize) -> T {
    (0..4).fold(T::zero(), |mut sum, i| {
        sum += env.witness_curr(lsb + 3 * i) * T::from(2u64).pow(4 * i as u64);
        sum
    })
}
