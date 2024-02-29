use crate::keccak::{environment::KeccakEnv, KeccakColumn};
use ark_ec::AffineCurve;
use kimchi::{
    circuits::gate::CurrOrNext,
    folding::{
        expressions::FoldingColumnTrait, FoldingConfig, FoldingEnv, Instance, Side, Sponge, Witness,
    },
};
use mina_curves::pasta::Pallas;
use poly_commitment::commitment::CommitmentCurve;

impl FoldingColumnTrait for KeccakColumn {
    fn is_witness(&self) -> bool {
        // All Keccak columns are witness columns
        true
    }
}

impl<F, I, W, Col, Chal> FoldingEnv<F, I, W, Col, Chal> for KeccakEnv<F> {
    type Structure = ();

    fn zero_vec(&self) -> Vec<F> {
        todo!()
    }

    fn col(&self, _col: Col, _curr_or_next: CurrOrNext, _side: Side) -> &Vec<F> {
        todo!()
    }

    fn challenge(&self, _challenge: Chal, _side: Side) -> F {
        todo!()
    }

    fn new(_structure: &Self::Structure, _instances: [&I; 2], _witnesses: [&W; 2]) -> Self {
        todo!()
    }

    fn lagrange_basis(&self, _i: usize) -> &Vec<F> {
        todo!()
    }

    fn alpha(&self, _i: usize, _side: Side) -> F {
        todo!()
    }
}

pub(crate) struct KeccakExample;

impl<G: CommitmentCurve> Sponge<G> for KeccakExample {
    fn challenge(_absorbe: &[poly_commitment::PolyComm<G>; 2]) -> <G>::ScalarField {
        panic!("just for test")
    }
}

impl<G: CommitmentCurve> Instance<G> for KeccakExample {
    fn combine(_a: Self, _b: Self, _challenge: G::ScalarField) -> Self {
        KeccakExample
    }
}

impl<G: CommitmentCurve> Witness<G> for KeccakExample {
    fn combine(_a: Self, _b: Self, _challenge: G::ScalarField) -> Self {
        KeccakExample
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct KeccakConfig;
impl FoldingConfig for KeccakConfig {
    type Column = KeccakColumn;

    type Challenge = ();

    type Curve = Pallas;

    type Srs = poly_commitment::srs::SRS<Pallas>;

    type Sponge = KeccakExample;

    type Instance = KeccakExample;

    type Witness = KeccakExample;

    type Structure = ();

    type Env = KeccakEnv<<Pallas as AffineCurve>::ScalarField>;

    fn rows() -> usize {
        todo!()
    }
}
