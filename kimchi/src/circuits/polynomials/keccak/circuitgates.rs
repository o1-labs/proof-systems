//~ The keccak gadget is comprised of _ circuit gates (KeccakXOR, .., and Zero)
//~
//~ Keccak works with 64-bit words. The state is represented using $5\times 5$ matrix
//~ of 64 bit words. Each compression step of Keccak consists of 24 rounds. Let us
//~ denote the state matrix with A. Each round then consists of the following 5 steps:
//~
//~ \begin{align}
//~ C[x] &= A[x,0] \oplus A[x,1] \oplus A[x,2] \oplus A[x,3] \oplus A[x,4] \\
//~ D[x] &= C[x-1] \oplus ROT(C[x+1],1) \\
//~ E[x,y] &= A[x,y]  \oplus D[x] \\
//~ B[y,2x+3y] &= ROT(E[x,y],\rho[x,y]) \\
//~ F[x,y] &= B[x,y] \oplus ((NOT B[x+1,y]) AND B[x+2,y]) \\
//~ Fp[0,0] &= F[0,0] \oplus RC
//~ \end{align}
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
//~ ##### 32-bit decomposition gate
//~
//~ This is a basic operation that is typically done for 64-bit initial state and
//~ intermediate values.
//~
//~ Let `inp` be a 64-bit word. The constraint is: `in` $= 2^32 \cdot$ `in_hi` $+$ `in_lo`.
//~ It takes 3 cells for values `in`, `in_hi`, `in_lo`. We have not yet placed them w.r.t
//~ other rows of the Keccak computation; the only requirement is that all these cells be
//~ within the first 7 columns for permutation equation accessibility.
//
//~ ##### XOR gate
//~
//~ First we consider a XOR gate that checks that a 32-bit word `out` is the XOR of `in1` and `in2`.
//~ This gate will use 2 rows, with a `Xor` row followed by a `Zero` row.
//~
//~ | Gates |          `Xor`   |          `Zero`  |
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
//~ | Gates |    `Xor` |   `Zero` |    `Xor` |   `Zero` |
//~ | ----- | -------- | -------- | -------- | -------- |
//~ | Rows  |       0  |       1  |       2  |        3 |
//~ | Cols  |          |          |          |          |
//~ |     0 | `in1_lo` | `out_lo` | `in1_hi` | `out_hi` |
//~ |     1 |          | `in2_lo` |          | `in2_hi` |
//~ |     2 |          |          |          |          |
//~ |     3 |  `in2_0` |  `in2_4` |  `in2_8` | `in2_12` |
//~ |     4 |  `in2_1` |  `in2_5` |  `in2_9` | `in2_13` |
//~ |     5 |  `in2_2` |  `in2_6` | `in2_10` | `in2_14` |
//~ |     6 |  `in2_3` |  `in2_7` | `in2_11` | `in2_15` |
//~ |     7 |  `in1_0` |  `in1_4` |  `in2_8` | `in2_12` |
//~ |     8 |  `in1_1` |  `in1_5` |  `in2_9` | `in2_13` |
//~ |     9 |  `in1_2` |  `in1_6` | `in2_10` | `in2_14` |
//~ |    10 |  `in1_3` |  `in1_7` | `in2_11` | `in2_15` |
//~ |    11 |  `out_0` |  `out_4` |  `in2_8` | `in2_12` |
//~ |    12 |  `out_1` |  `out_5` |  `in2_9` | `in2_13` |
//~ |    13 |  `out_2` |  `out_6` | `in2_10` | `in2_14` |
//~ |    14 |  `out_3` |  `out_7` | `in2_11` | `in2_15` |
//~
//~ ```admonition::notice
//~  We could half the number of rows of the 64-bit XOR gadget by having lookups
//~  for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~ ```
//~
//~ ##### Gate types:
//~
//~ Different rows are constrained using different CircuitGate types
//~
//~  | Row | `CircuitGate` | Purpose                        |
//~  | --- | ------------- | ------------------------------ |
//~  |   0 | `Xor`         | Xor first 2 bytes of low  half |
//~  |   1 | `Zero`        | Xor last  2 bytes of low  half |
//~  |   2 | `Xor`         | Xor first 2 bytes of high half |
//~  |   3 | `Zero`        | Xor last  2 bytes of high half |
//~

use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentType},
    expr::{witness_curr, witness_next, ConstantExpr, Expr, E},
    gate::GateType,
};
use ark_ff::{FftField, One, Zero};

//~ ##### `Xor` - XOR constraints for 32-bit words
//~
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
//~ | Column |          `Curr`  |          `Next`  |
//~ | ------ | ---------------- | ---------------- |
//~ |      0 | copy     `in1`   | copy     `out`   |
//~ |      1 |                  | copy     `in2`   |
//~ |      2 |                  |                  |
//~ |      3 | plookup0 `in2_0` | plookup4 `in2_4` |
//~ |      4 | plookup1 `in2_1` | plookup5 `in2_5` |
//~ |      5 | plookup2 `in2_2` | plookup6 `in2_6` |
//~ |      6 | plookup3 `in2_3` | plookup8 `in2_7` |
//~ |      7 | plookup0 `in1_0` | plookup4 `in1_4` |
//~ |      8 | plookup1 `in1_1` | plookup5 `in1_5` |
//~ |      9 | plookup2 `in1_2` | plookup6 `in1_6` |
//~ |     10 | plookup3 `in1_3` | plookup7 `in1_7` |
//~ |     11 | plookup0 `out_0` | plookup4 `out_4` |
//~ |     12 | plookup1 `out_1` | plookup5 `out_5` |
//~ |     13 | plookup2 `out_2` | plookup6 `out_6` |
//~ |     14 | plookup3 `out_3` | plookup7 `out_7` |
//~

#[derive(Default)]
pub struct Xor<F>(PhantomData<F>);

impl<F> Argument<F> for Xor<F>
where
    F: FftField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Xor);
    const CONSTRAINTS: u32 = 3;

    // Constraints for Xor
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `in1`, `in2` and `out`
    //   * The actual XOR is performed thanks to the plookups.
    fn constraints() -> Vec<E<F>> {
        let mut constraints = vec![];

        let out_sum = four_bit(14);
        let in1_sum = four_bit(10);
        let in2_sum = four_bit(6);

        // Check first input is well formed
        constraints.push(in1_sum - witness_curr(0));
        // Check second input is well formed
        constraints.push(in2_sum - witness_next(1));
        // Check output input is well formed
        constraints.push(out_sum - witness_next(0));

        constraints
    }
}

/// Computes the decomposition of a 32-bit word whose most significant 4-bit crumb
/// is located in the `max` column of `witness_next`. The layout is the following:
///
/// |        | max - 3 | max - 2 | max - 1 |     max |
/// | ------ | ------- | ------- | ------- | ------- |
/// | `Curr` |  crumb0 |  crumb1 |  crumb2 |  crumb3 |
/// | `Next` |  crumb4 |  crumb5 |  crumb6 |  crumb7 |
///
fn four_bit<F: FftField>(max: usize) -> E<F> {
    let mut sum = E::zero();
    let two: Expr<ConstantExpr<F>> = E::one() + E::one();
    for i in (max - 4..max).rev() {
        sum = two.clone() * sum + witness_next(i);
    }
    for i in (max - 4..max).rev() {
        sum = two.clone() * sum + witness_curr(i);
    }
    sum
}
