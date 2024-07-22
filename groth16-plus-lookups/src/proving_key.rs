use ark_ff::FftField;
use ark_poly::Radix2EvaluationDomain as D;

pub struct TrustedSetupProverOutputs<G1, G2> {
    pub left_fixed_randomizer: G1,
    pub right_fixed_randomizer: (G1, G2),
    pub output_fixed_randomizer: (G1, G2),
    pub left_commitments: Box<[G1]>,
    pub right_commitments: Box<[G2]>,
    pub out_commitments: Box<[G1]>,
    pub quotient_commitments: Box<[G1]>,
}

pub struct CircuitLayout<F: FftField> {
    pub public_input_size: usize,
    pub a_contributions: Box<[Box<[(usize, F)]>]>,
    pub b_contributions: Box<[Box<[(usize, F)]>]>,
    pub c_contributions: Box<[Box<[(usize, F)]>]>,
    pub domain: D<F>,
    pub domain_d2: D<F>,
}
