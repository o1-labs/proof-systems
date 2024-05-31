use crate::instance_witness::Witness;
use crate::{expressions::FoldingColumnTrait, Instance};
use crate::{FoldingConfig, FoldingEnv, Side};
use kimchi::circuits::gate::CurrOrNext;
use kimchi::curve::KimchiCurve;
use poly_commitment::commitment::CommitmentCurve;
use poly_commitment::srs;
use std::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Index};

/// An standard folding config that should supports  
/// `G`: any curve  
/// `Col`: any column implementing [FoldingColumnTrait]  
/// `Chall`: any challenge  
/// `Sel`: any dynamic selector  
/// `Str`: structures that can be indexed by `Col`, thus implementing `Index<Col>`  
/// `I`: instances (implementing [Instance]) that can be indexed by `Chall`
/// `W`: witnesses (implementing [Witness]) that can be indexed by `Col` and `Sel`
pub struct StandardConfig<G, Col, Chall, I, W, Sel = (), Str = ()>(
    PhantomData<(G, Col, Chall, Sel, Str, I, W)>,
);

// manual implementation to avoid the bounds of the macro, same as what the macro would create,
// but without unnecessary bounds

impl<G, Col, Chall, Sel, Str, I, W> PartialEq for StandardConfig<G, Col, Chall, Sel, Str, I, W> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<G, Col, Chall, Sel, Str, I, W> Hash for StandardConfig<G, Col, Chall, Sel, Str, I, W> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<G, Col, Chall, Sel, Str, I, W> Debug for StandardConfig<G, Col, Chall, Sel, Str, I, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StandardConfig").field(&self.0).finish()
    }
}

impl<G, Col, Chall, Sel, Str, I, W> Clone for StandardConfig<G, Col, Chall, Sel, Str, I, W> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

//implementing FoldingConfig
impl<G, Col, Chall, Sel, Str, I, W> FoldingConfig for StandardConfig<G, Col, Chall, Sel, Str, I, W>
where
    Self: 'static,
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Witness<G> + Clone,
    W: Index<Col, Output = Vec<G::ScalarField>> + Index<Sel, Output = Vec<G::ScalarField>>,
    Col: Hash + Eq + Debug + Clone + FoldingColumnTrait,
    Sel: Ord + Copy + Hash + Debug,
    Chall: Hash + Eq + Debug + Copy,
    Str: Clone + Index<Col, Output = Vec<G::ScalarField>>,
{
    type Column = Col;

    type Selector = Sel;

    type Challenge = Chall;

    type Curve = G;

    type Srs = srs::SRS<G>;

    type Instance = I;

    type Witness = W;

    type Structure = Str;

    type Env = Env<G, Col, Chall, Sel, Str, I, W>;
}
//a generic Index based environment
pub struct Env<G, Col, Chall, Sel, Str, I, W>
where
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Witness<G> + Clone,
    W: Index<Col, Output = Vec<G::ScalarField>> + Index<Sel, Output = Vec<G::ScalarField>>,
{
    instances: [I; 2],
    witnesses: [W; 2],
    structure: Str,
    _todo: PhantomData<(G, Col, Chall, Sel, Str)>,
}

//implementing FoldingEnv
impl<G, Col, Chall, Sel, Str, I, W> FoldingEnv<G::ScalarField, I, W, Col, Chall, Sel>
    for Env<G, Col, Chall, Sel, Str, I, W>
where
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Witness<G> + Clone,
    W: Index<Col, Output = Vec<G::ScalarField>> + Index<Sel, Output = Vec<G::ScalarField>>,
    Col: FoldingColumnTrait,
    Sel: Copy,
    Str: Clone + Index<Col, Output = Vec<G::ScalarField>>,
{
    type Structure = Str;

    fn new(structure: &Self::Structure, instances: [&I; 2], witnesses: [&W; 2]) -> Self {
        // cloning for now, ideally should work with references, but that requires deeper
        // refactorings of folding
        let instances = instances.map(Clone::clone);
        let witnesses = witnesses.map(Clone::clone);
        let structure = structure.clone();
        Self {
            instances,
            witnesses,
            structure,
            _todo: PhantomData,
        }
    }

    fn challenge(&self, challenge: Chall, side: Side) -> G::ScalarField {
        let instance = match side {
            Side::Left => &self.instances[0],
            Side::Right => &self.instances[1],
        };
        // handled through Index in I
        instance[challenge]
    }

    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<G::ScalarField> {
        // TODO: support Next
        assert!(matches!(curr_or_next, CurrOrNext::Curr));
        let witness = match side {
            Side::Left => &self.witnesses[0],
            Side::Right => &self.witnesses[1],
        };
        // this should hold as long the Index implementations are consistent with the
        // FoldingColumnTrait implementation.
        // either search in witness for witness columns, or in the structure otherwise
        if col.is_witness() {
            &witness[col]
        } else {
            &self.structure[col]
        }
    }

    fn selector(&self, s: &Sel, side: Side) -> &Vec<G::ScalarField> {
        //similar to the witness case of col, as expected
        let witness = match side {
            Side::Left => &self.witnesses[0],
            Side::Right => &self.witnesses[1],
        };
        &witness[*s]
    }
}

#[cfg(test)]
#[cfg(feature = "bn254")]
mod example {
    use super::StandardConfig;
    use crate::{
        examples::{BaseSponge, Curve, Fp},
        expressions::{FoldingColumnTrait, FoldingCompatibleExprInner},
        instance_witness::Foldable,
        FoldingCompatibleExpr, Instance, Witness,
    };
    use ark_ec::ProjectiveCurve;
    use kimchi::{
        circuits::{expr::Variable, gate::CurrOrNext},
        curve::KimchiCurve,
    };
    use std::{marker::PhantomData, ops::Index};

    #[derive(Clone, Debug)]
    struct MyInstance<G: KimchiCurve> {
        commitments: [G; 3],
        beta: G::ScalarField,
        gamma: G::ScalarField,
    }

    impl<G: KimchiCurve> Foldable<G::ScalarField> for MyInstance<G> {
        fn combine(mut a: Self, b: Self, challenge: G::ScalarField) -> Self {
            for (a, b) in a.commitments.iter_mut().zip(b.commitments) {
                *a = *a + b.mul(challenge).into_affine();
            }
            a
        }
    }
    impl<G: KimchiCurve> Instance<G> for MyInstance<G> {
        fn to_absorb(&self) -> (Vec<<G>::ScalarField>, Vec<G>) {
            (vec![], self.commitments.to_vec())
        }

        fn get_alphas(&self) -> &crate::Alphas<<G>::ScalarField> {
            todo!()
        }
    }
    #[derive(Clone, Debug)]
    struct MyWitness<G: KimchiCurve> {
        columns: [Vec<G::ScalarField>; 3],
    }

    impl<G: KimchiCurve> Foldable<G::ScalarField> for MyWitness<G> {
        fn combine(mut a: Self, b: Self, challenge: G::ScalarField) -> Self {
            for (a, b) in a.columns.iter_mut().zip(b.columns) {
                for (a, b) in a.iter_mut().zip(b) {
                    *a = *a + b * challenge;
                }
            }
            a
        }
    }
    impl<G: KimchiCurve> Witness<G> for MyWitness<G> {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum MyCol {
        A,
        B,
        C,
    }

    impl FoldingColumnTrait for MyCol {
        fn is_witness(&self) -> bool {
            true
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum MyChallenge {
        Beta,
        Gamma,
    }

    //indexing
    impl<G: KimchiCurve> Index<MyCol> for MyWitness<G> {
        type Output = Vec<G::ScalarField>;

        fn index(&self, index: MyCol) -> &Self::Output {
            let index = match index {
                MyCol::A => 0,
                MyCol::B => 1,
                MyCol::C => 2,
            };
            &self.columns[index]
        }
    }
    impl<G: KimchiCurve> Index<()> for MyWitness<G> {
        type Output = Vec<G::ScalarField>;

        fn index(&self, _index: ()) -> &Self::Output {
            unreachable!()
        }
    }
    impl<G: KimchiCurve> Index<MyChallenge> for MyInstance<G> {
        type Output = G::ScalarField;

        fn index(&self, index: MyChallenge) -> &Self::Output {
            match index {
                MyChallenge::Beta => &self.beta,
                MyChallenge::Gamma => &self.gamma,
            }
        }
    }
    #[derive(Clone, Default)]
    struct EmptyStructure<G: KimchiCurve>(PhantomData<G::ScalarField>);
    impl<G: KimchiCurve> Index<MyCol> for EmptyStructure<G> {
        type Output = Vec<G::ScalarField>;

        fn index(&self, _index: MyCol) -> &Self::Output {
            panic!("shouldn'r reach this point, as there are only witness columns involved");
        }
    }

    type MyConfig<G> =
        StandardConfig<G, MyCol, MyChallenge, (), EmptyStructure<G>, MyInstance<G>, MyWitness<G>>;

    fn constraint<G: KimchiCurve>() -> FoldingCompatibleExpr<MyConfig<G>> {
        let column = |col| {
            FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Cell(Variable {
                col,
                row: CurrOrNext::Curr,
            }))
        };
        let chall =
            |chall| FoldingCompatibleExpr::Atom(FoldingCompatibleExprInner::Challenge(chall));
        let a = column(MyCol::A);
        let b = column(MyCol::B);
        let c = column(MyCol::C);
        let beta = chall(MyChallenge::Beta);
        let gamma = chall(MyChallenge::Gamma);
        (a + b - c) * (beta + gamma)
    }

    #[allow(dead_code)]
    fn fold(pairs: [(MyInstance<Curve>, MyWitness<Curve>); 2]) {
        use crate::FoldingScheme;
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
        use mina_poseidon::FqSponge;

        let constraints = vec![constraint()];
        let domain = Radix2EvaluationDomain::<Fp>::new(2).unwrap();
        let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
        srs.add_lagrange_basis(domain);
        let structure = EmptyStructure::default();

        let (scheme, _) =
            FoldingScheme::<MyConfig<Curve>>::new(constraints, &srs, domain, &structure);

        let [left, right] = pairs;
        let left = (left.0, left.1);
        let right = (right.0, right.1);

        let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());
        scheme.fold_instance_witness_pair(left, right, &mut fq_sponge);
    }
}
