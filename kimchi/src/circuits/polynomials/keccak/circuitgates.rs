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
//~ ```admonition::notice
//~  We could half the number of rows of the 64-bit XOR gadget by having lookups
//~  for 8 bits at a time, but for now we will use the 4-bit XOR table that we have.
//~  If we had 8-bit XOR table, we could half rotation rows as well but with twice as many rotation gate types.
//~ ```
//~
//~ ##### Rotation gates
//~
//~ Notice that the keccak hash function involves rotation operations with different offsets at different points of the computation.
//~ In fact, every word is rotated by a different offset at a certain stage. Instead of creating different gates for each offset,
//~ we take the following approach that is much more efficient.
//~ - 1 bit
//~ - 2 bits
//~ - 3 bits
//~ - a multiple of 4 bits
//~ To rotate a word by $n = 4m + r$ bits where $r < 4$, we first invoke the gate for rotation by $m/2$ bytes.
//~ Then we invoke the gate to rotate by r bits.
//~
use std::marker::PhantomData;

use crate::circuits::{
    argument::{Argument, ArgumentEnv, ArgumentType},
    expr::constraints::ExprOps,
    gate::GateType,
};
use ark_ff::PrimeField;

//~ ##### `KeccakRot` - Constraints for rotation by 1 or 2 or 3 bits
//~
//~ * This circuit gate is used to constrain that a 64-bit word is rotated by 1-2-3 bit to its shifted value.
//~ * The rotation is performed towards the most significant side (thus, the new LSB is fed with the old MSB).
//~ * This gate operates on the `Curr` row and the `Next` row (if we stick to 4-bit XOR table).
//~
//~ It uses three different types of constraints
//~ * copy    - copy to another cell (32-bits)
//~ * plookup - xor-table plookup (4-bits)
//~
//~ Consider rotating 64 bit $C[x]$ by 1, 2 or 3 bits. We first decompose it to $C[x]_{lo}$ and $C[x]_{hi}$
//~ (32-bit components). Consider $C[x]_{lo}. In the gate described below, we first
//~ decompose $C[x]_{lo}$ into bytes. For each byte, we also consider the MSBs; denote
//~ the MSBs of $C[x]_i$ by $c[x]_i$. We constrain that $CS[x]_i = 2^n(C[x]_i − 2^(4-n) c[x]_i )+c[x]_{i−1}$.
//~ (To clarify, $C[x]_i$ is a crumb and $c[x]_i$ is the most significant bit of $C[x]_i$). Note
//~ that we need to “copy” the edge elements between $C[x]_{lo}$ and $C[x]_{hi}$ as shown in
//~ the diagram. We also need to check that $(C[x]_i − c[x]_i , C[x]_i − c[x]_i , 0)$ in XOR
//~ table to ensure that $c[x]_i$ is the MSB of $C[x]_i$. TODO: ??
//~
//~ Here we show the full layout for the whole 64-bit word, which is a concatenation of the following gates:
//~
//~  | Row | `CircuitGate` | Purpose                        |
//~  | --- | ------------- | ------------------------------ |
//~  |   0 | `KeccakRot`   | Rot first 2 bytes of low  half |
//~  |   1 | `Zero`        | Rot last  2 bytes of low  half |
//~  |   2 | `KeccakRot`   | Rot first 2 bytes of high half |
//~  |   3 | `Zero`        | Rot last  2 bytes of high half |
//~
//~ The 4-bit crumbs are assumed to be laid out with `0` being the least significant crumb.
//~ We split the 64-bit word into two 32-bit halves and then split each of these into 4-bit crumbs `crumb_i`.
//~ We call the `n` most significant bits of each crumb `msb_i` (where `n` is a coefficient of the gate and ranges between 1,2,3)
//~
//~ | Gate   | `KeccakRot`    | `Zero          | `KeccakRot`     | `Zero`          |
//~ | ------ | -------------- | -------------- | --------------- | --------------- |
//~ | Column | `Curr`         | `Next`         | `Curr`          | `Next`          |
//~ | ------ | -------------- | -------------- | --------------- | --------------- |
//~ |      0 | copy `lo`      | copy `msb_15`  | copy   `hi`     | copy  `msb_7`   |
//~ |      1 |                | copy `sft_lo`  |                 | copy  `sft_hi`  |
//~ |      2 |                |                |                 |                 |
//~ |      3 | copy `sft_0`   | copy `sft_4`   | copy `sft_8`    | copy `sft_12`   |
//~ |      4 | copy `sft_1`   | copy `sft_5`   | copy `sft_9`    | copy `sft_13`   |
//~ |      5 | copy `sft_2`   | copy `sft_6`   | copy `sft_10`   | copy `sft_14`   |
//~ |      6 | copy `sft_3`   | copy `sft_7`   | copy `sft_11`   | copy `sft_15`   |
//~ |      7 |      `msb_0`   |      `msb_4`   |      `msb_8`    |      `msb_12`   |
//~ |      8 |      `msb_1`   |      `msb_5`   |      `msb_9`    |      `msb_13`   |
//~ |      9 |      `msb_2`   |      `msb_6`   |      `msb_10`   |      `msb_14`   |
//~ |     10 |      `msb_3`   |      `msb_7`   |      `msb_11`   |      `msb_15`   |
//~ |     11 |      `crumb_0` |      `crumb_4` |      `crumb_8`  |      `crumb_12` |
//~ |     12 |      `crumb_1` |      `crumb_5` |      `crumb_9`  |      `crumb_13` |
//~ |     13 |      `crumb_2` |      `crumb_6` |      `crumb_10` |      `crumb_14` |
//~ |     14 |      `crumb_3` |      `crumb_7` |      `crumb_11` |      `crumb_15` |
//~
#[derive(Default)]
pub struct KeccakRot<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakRot<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakRot);
    const CONSTRAINTS: u32 = 10;

    // Constraints for rotation by 1, 2 or 3 bits
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `half` into crumbs and check rotation of 1, 2 or 3 bits between them
    //   * The actual XOR is performed thanks to the plookups.
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let mut constraints = vec![];

        let half = env.witness_curr(0);
        let half_decomp = four_bit(env, 10);

        let shift = env.witness_next(1);
        let shift_decomp = four_bit(env, 6);

        let aux = env.witness_curr(1); // TODO: substitute by coefficient
        let one = T::one();
        let two = T::one().double();
        let three = T::one().double() + T::one();

        // Check half is well decomposed
        constraints.push(half_decomp - half);
        // Check shift is well decomposed
        constraints.push(shift_decomp - shift);
        // Check crumb rotations
        let rot1 = rot_bits(&env, 1);
        let rot2 = rot_bits(&env, 2);
        let rot3 = rot_bits(&env, 3);
        for i in 0..rot1.len() {
            // 8
            constraints.push(
                rot1[i].clone() * (aux.clone() - two.clone()) * (aux.clone() - three.clone())
                    + rot2[i].clone() * (aux.clone() - one.clone()) * (aux.clone() - three.clone())
                    + rot3[i].clone() * (aux.clone() - one.clone()) * (aux.clone() - two.clone()),
            );
        }

        // TODO: how do we check that the msb is only 1 bit? binary check?

        constraints
    }
}

//~ ###### Rotation by integral multiple of 4 bits
//~
//~ Consider rotating 64 bit $E$ by a multiple $m$ of 4 bits to get $B$. We first decompose
//~ $E$ into chunks of 8 bits $E_{14,15}$ , $E_{12,13}$ , $E_{10,11}$ , $E_{8,9} , $E_{6,7}$ , $E_{4,5}$ , $E_{2,3}$ , $E_{0,1}$ so that
//~ $E = \sum_{i = 0}^7 (2^8)^i \cdot E_{2i,2i+1}$. Here, we chose the subscripts this way to continue
//~ the byte narrative while temporarily switching to 8-bit chunks. $E_{2i,2i+1}$ is the ith 8-bit chunk.
//~
//~ Depending on the value of m we write the corresponding weights for these 8-bit values like in
//~ the decomposition of $B$. The weight corresponding to $E_{2i,2i+1}$ is denoted by $w_{2i,2i+1}$. However,
//~ depending on the value of $m$, there can be one 8-bit component that could get split between the
//~ most significant and the least significant part of B. In the example in the diagram, it is $E_{8,9}$.
//~ For this element the weight assigned will be $0$; we will incorporate this element by splitting it
//~ up with the constraint $E_{8,9} = 2^4 E_9 + E_8$. We will incorporate these elements by always giving
//~ the weight $(2^4)^{15} to the lower significant part – namely $E_8$ in this example and $1$ to the other
//~ part $E_9$. The values of the weights will be enforced using permutation polynomial.
//~
//~ Towards specifying the right 8-bit element to be split, we will use a sequence of separate weights
//~ $c_{2i,2i+1}$ which are zeroes for all $E_{2i,2i+1}$ except $c_{8,9}$. The weights $c_{2i,2i+1}$ will be combined into
//~ a 32 bit value $c$ whose value will be enforced using the permutation polynomial.
//~

//~ ##### `KeccakXor` - XOR constraints for 32-bit words
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
//~ ##### XOR gate
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

    // Constraints for Xor
    //   * Operates on Curr and Next rows
    //   * Constrain the decomposition of `in1`, `in2` and `out`
    //   * The actual XOR is performed thanks to the plookups.
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        let mut constraints = vec![];

        let out_sum = four_bit(env, 14);
        let in1_sum = four_bit(env, 10);
        let in2_sum = four_bit(env, 6);

        // Check first input is well formed
        constraints.push(in1_sum - env.witness_curr(0));
        // Check second input is well formed
        constraints.push(in2_sum - env.witness_next(1));
        // Check output input is well formed
        constraints.push(out_sum - env.witness_next(0));

        constraints
    }
}

//~ ##### `KeccakBits` - 32-bit decomposition gate
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
//~ It uses one type of constraints
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
pub struct KeccakBits<F>(PhantomData<F>);

impl<F> Argument<F> for KeccakBits<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::KeccakBits);
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
    let half_bits = two.pow(32);
    env.witness_curr(idx) - (env.witness_curr(idx + 2) * half_bits + env.witness_curr(idx + 1))
}

// Computes the decomposition of a 32-bit word whose most significant 4-bit crumb
// is located in the `max` column of `witness_next`. The layout is the following:
//
// |        | max - 3 | max - 2 | max - 1 |     max |
// | ------ | ------- | ------- | ------- | ------- |
// | `Curr` |  crumb0 |  crumb1 |  crumb2 |  crumb3 |
// | `Next` |  crumb4 |  crumb5 |  crumb6 |  crumb7 |
//
fn four_bit<F: PrimeField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>, max: usize) -> T {
    let mut sum = T::zero();
    let two = T::one() + T::one();
    let four_bit = two.pow(4);
    for i in (max - 3..=max).rev() {
        sum = four_bit.clone() * sum + env.witness_next(i);
    }
    for i in (max - 3..=max).rev() {
        sum = four_bit.clone() * sum + env.witness_curr(i);
    }
    sum
}

// Computes the rotation of eight 4-bit crumbs by 1,2 or 3 bits to the most significant position.
// It performs the following operation:
// `shift_i = 2^b · ( crumb_i - 2^{4-b} · msb_i ) + msb_{i-1}`
// This means for each possible value of the rotation bit:
// - Rot 1-bit: `shift_i = 2 · ( crumb_i - 8 · msb_i ) + msb_{i-1}`
// - Rot 2-bit: `shift_i = 4 · ( crumb_i - 4 · msb_i ) + msb_{i-1}`
// - Rot 3-bit: `shift_i = 8 · ( crumb_i - 2 · msb_i ) + msb_{i-1}`
//
fn rot_bits<F: PrimeField, T: ExprOps<F>>(env: &ArgumentEnv<F, T>, rot: u64) -> Vec<T> {
    let mut constraints = vec![];
    let two = T::one() + T::one();
    let term = two.pow(rot);
    let weight = two.pow(4 - rot);
    let mut prev = env.witness_next(0); // first previous msb is located in auxiliary position
    for i in 0..4 {
        // curr row
        let shift = env.witness_curr(3 + i);
        let msb = env.witness_curr(7 + i);
        let crumb = env.witness_curr(11 + i);
        let rot = term.clone() * (crumb - weight.clone() * msb.clone()) + prev;
        constraints.push(rot - shift);
        prev = msb;
    }
    // next row
    for i in 0..4 {
        let shift = env.witness_next(3 + i);
        let msb = env.witness_next(7 + i);
        let crumb = env.witness_next(11 + i);
        let rot = term.clone() * (crumb - weight.clone() * msb.clone()) + prev;
        constraints.push(rot - shift);
        prev = msb;
    }
    constraints
}
