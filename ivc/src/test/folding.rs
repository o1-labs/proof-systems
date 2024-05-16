mod addition {
    use std::ops::Index;

    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use folding::{
        expressions::FoldingColumnTrait,
        plonkish::{PlonkishEnvironment, PlonkishInstance, PlonkishTrace, PlonkishWitness},
        FoldingConfig,
    };
    use poly_commitment::srs::SRS;
    use strum::EnumCount;

    use crate::test::{columns::AdditionColumn, BN254G1Affine, Fp};

    #[derive(Clone, Debug, Copy, Eq, PartialEq, Hash)]
    pub struct Config;

    impl FoldingColumnTrait for AdditionColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    type Witness = PlonkishWitness<{ AdditionColumn::COUNT }, Fp>;

    impl Index<AdditionColumn> for Witness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: AdditionColumn) -> &Self::Output {
            match index {
                AdditionColumn::A => &self.witness.cols[0],
                AdditionColumn::B => &self.witness.cols[1],
                AdditionColumn::C => &self.witness.cols[2],
            }
        }
    }

    impl FoldingConfig for Config {
        type Column = AdditionColumn;
        type Selector = ();
        type Challenge = ();
        type Curve = BN254G1Affine;
        type Srs = SRS<BN254G1Affine>;
        type Instance = PlonkishInstance<{ AdditionColumn::COUNT }, BN254G1Affine>;
        type Witness = Witness;
        type Structure = PlonkishTrace;
        type Env = PlonkishEnvironment<{ AdditionColumn::COUNT }, Self, PlonkishTrace>;
    }
}
