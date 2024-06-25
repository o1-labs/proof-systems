use ark_ff::FftField;
use ark_poly::{Evaluations, Radix2EvaluationDomain as R2D};
use folding::{instance_witness::Foldable, Witness};
use kimchi_msm::{columns::Column, witness::Witness as GenericWitness};
use poly_commitment::commitment::CommitmentCurve;
use std::ops::Index;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlonkishWitness<const N_COL: usize, const N_FSEL: usize, F: FftField> {
    pub witness: GenericWitness<N_COL, Evaluations<F, R2D<F>>>,
    // This does not have to be part of the witness... can be a static
    // precompiled object.
    pub fixed_selectors: GenericWitness<N_FSEL, Evaluations<F, R2D<F>>>,
}

impl<const N_COL: usize, const N_FSEL: usize, F: FftField> Foldable<F>
    for PlonkishWitness<N_COL, N_FSEL, F>
{
    fn combine(mut a: Self, b: Self, challenge: F) -> Self {
        for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
            for (a, b) in a.evals.iter_mut().zip(b.evals) {
                *a += challenge * b;
            }
        }
        a
    }
}

impl<const N_COL: usize, const N_FSEL: usize, Curve: CommitmentCurve> Witness<Curve>
    for PlonkishWitness<N_COL, N_FSEL, Curve::ScalarField>
{
}

impl<const N_COL: usize, const N_FSEL: usize, F: FftField> Index<Column>
    for PlonkishWitness<N_COL, N_FSEL, F>
{
    type Output = Vec<F>;

    /// Map a column alias to the corresponding witness column.
    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::Relation(i) => &self.witness.cols[i].evals,
            Column::FixedSelector(i) => &self.fixed_selectors[i].evals,
            other => panic!("Invalid column index: {other:?}"),
        }
    }
}

// for selectors, () in this case as we have none
impl<const N_COL: usize, const N_FSEL: usize, F: FftField> Index<()>
    for PlonkishWitness<N_COL, N_FSEL, F>
{
    type Output = Vec<F>;

    fn index(&self, _index: ()) -> &Self::Output {
        unreachable!()
    }
}
