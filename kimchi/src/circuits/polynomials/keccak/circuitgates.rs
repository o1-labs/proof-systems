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
//~ The values are in the table below extracted from the Keccak reference
//~ <https://keccak.team/files/Keccak-reference-3.0.pdf>
//~
//~ |       | x = 3 | x = 4 | x = 0 | x = 1 | x = 2 |
//~ | ----- | ----- | ----- | ----- | ----- | ----- |
//~ | y = 2 |  155  |  231  |    3  |   10  |  171  |
//~ | y = 1 |   55  |  276  |   36  |  300  |    6  |
//~ | y = 0 |   28  |   91  |    0  |    1  |  190  |
//~ | y = 4 |  120  |   78  |  210  |   66  |  253  |
//~ | y = 3 |   21  |  136  |  105  |   45  |   15  |
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
    expr::constraints::ExprOps,
    gate::GateType,
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
