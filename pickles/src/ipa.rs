use ark_ff::{FftField, PrimeField};

/// Inner-Product Argument Accumulator.
///
/// An implementation of the verifier for PC_DL from
/// "Proof-Carrying Data from Accumulation Schemes", Section 2.4.1 and Appendix A (p. 49)
/// https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2020/499&version=20200929:225643&file=499.pdf
///
/// Note that verifying the accumulation requires two proofs,
/// because it involves both group operations over the base field and
/// the invocation of a "random oracle" to produce elements of the scalar field.
pub struct Accumulator<F: PrimeField + FftField> {
    challenges: Vec<F>, // challenges passed from "Fq" to "Fq", essentially pass-through
}
