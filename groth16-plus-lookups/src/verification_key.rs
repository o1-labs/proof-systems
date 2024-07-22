pub struct VerificationKey<G1, G2> {
    pub left_fixed_randomizer: G1,
    pub right_fixed_randomizer: G2,
    pub output_fixed_randomizer: G2,
    pub public_input_randomizer: G2,
    pub public_input_commitments: Box<[G1]>,
}
