use std::ops::Index;

use folding::standard_config::StandardConfig;
use kimchi::curve::KimchiCurve;
use kimchi_msm::columns::Column;

use crate::plonkish_lang::{PlonkishChallenge, PlonkishInstance, PlonkishWitness};

#[derive(Clone)]
/// Generic structure containing column vectors.
pub struct GenericVecStructure<G: KimchiCurve>(pub Vec<Vec<G::ScalarField>>);

impl<G: KimchiCurve> Index<Column> for GenericVecStructure<G> {
    type Output = [G::ScalarField];

    fn index(&self, index: Column) -> &Self::Output {
        match index {
            Column::FixedSelector(i) => &self.0[i],
            _ => panic!("should not happen"),
        }
    }
}

#[allow(clippy::type_complexity)]
pub struct Config<
    const N_COL: usize,
    const N_FSEL: usize,
    const N_CHALS: usize,
    const N_ALPHAS_QUAD: usize,
    G: KimchiCurve,
>(
    pub  StandardConfig<
        G,
        Column,
        PlonkishChallenge,
        PlonkishInstance<G, N_COL, N_CHALS, N_ALPHAS_QUAD>, // TODO check if it's quad or not
        PlonkishWitness<N_COL, N_FSEL, G::ScalarField>,
        (),
        GenericVecStructure<G>,
    >,
);
