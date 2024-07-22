pub struct TrustedSetupProverOutputs<G1, G2> {
    pub left_fixed_randomizer: G1,
    pub right_fixed_randomizer: G2,
    pub output_fixed_randomizer: (G1, G2),
    pub left_commitments: Box<[G1]>,
    pub right_commitments: Box<[G2]>,
    pub out_commitments: Box<[G1]>,
    pub quotient_commitments: Box<[G1]>,
}
