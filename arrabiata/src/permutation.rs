use ark_ff::PrimeField;

pub enum PermutationSign {
    Num,
    Den,
}

/// Represent a value that will be accumulated in the permutation acumulator
#[allow(dead_code)]
pub struct Permutation<F: PrimeField> {
    sign: PermutationSign,
    idx: u64,
    v: F,
}
