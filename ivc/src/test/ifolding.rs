pub mod addition {
    use std::ops::Index;

    use ark_ff::FftField;
    use kimchi_msm::{columns::Column, witness::Witness as GenericWitness};

    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use folding::{
        expressions::FoldingColumnTrait,
        plonkish::{PlonkishEnvironment, PlonkishInstance, PlonkishTrace},
        FoldingConfig, Witness,
    };
    use poly_commitment::{commitment::CommitmentCurve, srs::SRS};
    use strum::EnumCount;

    use crate::test::{columns::AdditionColumn, Curve, Fp};

    #[derive(Clone, Debug, Copy, Eq, PartialEq, Hash)]
    pub struct Config;

    impl FoldingColumnTrait for AdditionColumn {
        fn is_witness(&self) -> bool {
            true
        }
    }

    // pub type Witness = PlonkishWitness<{ AdditionColumn::COUNT }, Fp>;

    /// Includes the data witness columns and also the dynamic selector columns
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct PlonkishWitness {
        pub witness: GenericWitness<3, Evaluations<Fp, Radix2EvaluationDomain<Fp>>>,
    }

    impl Witness<Curve> for PlonkishWitness {
        fn combine(mut a: Self, b: Self, challenge: Fp) -> Self {
            for (a, b) in (*a.witness.cols).iter_mut().zip(*(b.witness.cols)) {
                for (a, b) in a.evals.iter_mut().zip(b.evals) {
                    *a += challenge * b;
                }
            }
            a
        }

        fn rows(&self) -> usize {
            self.witness.cols[0].evals.len()
        }
    }

    impl Index<Column> for PlonkishWitness {
        type Output = Evaluations<Fp, Radix2EvaluationDomain<Fp>>;

        /// Map a column alias to the corresponding witness column.
        fn index(&self, index: Column) -> &Self::Output {
            match index {
                Column::Relation(0) => &self.witness.cols[0],
                Column::Relation(1) => &self.witness.cols[1],
                Column::Relation(2) => &self.witness.cols[2],
                _ => panic!("Invalid column index"),
            }
        }
    }

    impl FoldingConfig for Config {
        type Column = Column;
        type Selector = ();
        type Challenge = ();
        type Curve = Curve;
        type Srs = SRS<Curve>;
        type Instance = PlonkishInstance<{ AdditionColumn::COUNT }, Curve>;
        type Witness = PlonkishWitness;
        type Structure = PlonkishTrace;
        type Env = PlonkishEnvironment<{ AdditionColumn::COUNT }, Self, PlonkishTrace>;
    }
}
