use crate::{
    folding::{Challenge, Curve, FoldingEnvironment, FoldingInstance, FoldingWitness, Fp},
    keccak::{column::ZKVM_KECCAK_COLS, KeccakColumn},
    DOMAIN_SIZE,
};
use ark_ff::Zero;
use kimchi::{
    circuits::gate::CurrOrNext,
    folding::{expressions::FoldingColumnTrait, BaseSponge, FoldingConfig, FoldingEnv, Side},
};

pub(crate) type KeccakFoldingWitness = FoldingWitness<ZKVM_KECCAK_COLS>;
pub(crate) type KeccakFoldingInstance = FoldingInstance<ZKVM_KECCAK_COLS>;
pub(crate) type KeccakFoldingEnvironment = FoldingEnvironment<ZKVM_KECCAK_COLS, KeccakStructure>;

// TODO: will contain information about the circuit structure
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct KeccakStructure;

// TODO
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct KeccakConfig;

impl FoldingColumnTrait for KeccakColumn {
    fn is_witness(&self) -> bool {
        // All Keccak columns are witness columns
        true
    }
}

impl FoldingEnv<Fp, KeccakFoldingInstance, KeccakFoldingWitness, KeccakColumn, Challenge>
    for KeccakFoldingEnvironment
{
    type Structure = KeccakStructure;

    fn new(
        structure: &Self::Structure,
        instances: [&KeccakFoldingInstance; 2],
        witnesses: [&KeccakFoldingWitness; 2],
    ) -> Self {
        let curr_witnesses = [witnesses[0].clone(), witnesses[1].clone()];
        let mut next_witnesses = curr_witnesses.clone();
        for side in next_witnesses.iter_mut() {
            for col in side.witness.cols.iter_mut() {
                col.evals.rotate_left(1);
            }
        }
        KeccakFoldingEnvironment {
            structure: structure.clone(),
            instances: [instances[0].clone(), instances[1].clone()],
            curr_witnesses,
            next_witnesses,
        }
    }

    fn zero_vec(&self) -> Vec<Fp> {
        vec![Fp::zero(); DOMAIN_SIZE]
    }

    fn col(&self, col: KeccakColumn, curr_or_next: CurrOrNext, side: Side) -> &Vec<Fp> {
        todo!()
    }

    fn challenge(&self, challenge: Challenge, side: Side) -> Fp {
        match challenge {
            Challenge::Beta => self.instances[side as usize].challenges[0],
            Challenge::Gamma => self.instances[side as usize].challenges[1],
            Challenge::JointCombiner => self.instances[side as usize].challenges[2],
        }
    }

    fn lagrange_basis(&self, i: usize) -> &Vec<Fp> {
        todo!()
    }

    fn alpha(&self, i: usize, side: Side) -> Fp {
        let instance = &self.instances[side as usize];
        instance.alphas.get(i).unwrap()
    }
}

impl FoldingConfig for KeccakConfig {
    type Column = KeccakColumn;
    type Challenge = Challenge;
    type Curve = Curve;
    type Srs = poly_commitment::srs::SRS<Curve>;
    type Sponge = BaseSponge;
    type Instance = FoldingInstance<ZKVM_KECCAK_COLS>;
    type Witness = FoldingWitness<ZKVM_KECCAK_COLS>;
    type Structure = KeccakStructure;
    type Env = KeccakFoldingEnvironment;

    fn rows() -> usize {
        DOMAIN_SIZE
    }
}
