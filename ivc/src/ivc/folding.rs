use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};
use folding::{instance_witness::Foldable, Witness};
use kimchi_msm::witness::Witness as GenericWitness;
use poly_commitment::commitment::CommitmentCurve;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlonkishWitness<const N_COL: usize, Fp: FftField> {
    pub witness: GenericWitness<N_COL, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
    // This does not have to be part of the witness... can be a static
    // precompiled object.
    pub fixed_selectors: Vec<Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
}

impl<const N_COL: usize, F: FftField> Foldable<F> for PlonkishWitness<N_COL, F> {
    fn combine(mut a: Self, b: Self, challenge: F) -> Self {
        for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

impl<const N_COL: usize, Curve: CommitmentCurve> Witness<Curve>
    for PlonkishWitness<N_COL, Curve::ScalarField>
{
}
