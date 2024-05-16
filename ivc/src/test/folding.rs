mod addition {
    use std::array;

    use ark_poly::{Evaluations, Radix2EvaluationDomain};
    use folding::Alphas;
    use strum::EnumCount;
    use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

    use crate::test::{columns::AdditionColumn, Fp, BN254};

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, EnumIter, EnumCountMacro)]
    pub enum Challenge {
        Beta,
        Gamma,
        JointCombiner,
    }

    struct Config;

    #[derive(Clone, Debug)]
    struct FoldingInstance {
        commitments: [BN254; AdditionColumn::COUNT],
        challenge: [Fp; Challenge::COUNT],
        alphas: Alphas<Fp>,
    }

    type FoldingWitness = [Evaluations<Fp, Radix2EvaluationDomain<Fp>>; AdditionColumn::COUNT];

    impl<const N: usize> Instance<BN254> for FoldingInstance<N> {
        fn combine(a: Self, b: Self, challenge: Fp) -> Self {
            Instance {
                commitments: array::from_fn(|i| {
                    a.commitments[i] + b.commitments[i].mul(challenge).into_affine()
                }),
                challenges: array::from_fn(|i| a.challenges[i] + challenge * b.challenges[i]),
                alphas: Alphas::combine(a.alphas, b.alphas, challenge),
            }
        }

        fn alphas(&self) -> &Alphas<G::ScalarField> {
            &self.alphas
        }
    }
}
