use crate::{expressions::FoldingColumnTrait, Instance};
use crate::{
    instance_witness::{self, Foldable},
    FoldingConfig, FoldingEnv, Side,
};
use ark_ff::Field;
use kimchi::circuits::gate::CurrOrNext;
use poly_commitment::commitment::CommitmentCurve;
use poly_commitment::srs;
use std::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Index};

pub struct FoldableWitness<F: Field, W, Col, Sel>
where
    W: Foldable<F> + Index<Col, Output = Vec<F>> + Index<Sel, Output = Vec<F>>,
{
    inner: W,
    _phantom: PhantomData<(F, Col, Sel)>,
}

impl<F: Field + Clone, W: Clone, Col, Sel> Clone for FoldableWitness<F, W, Col, Sel>
where
    W: Foldable<F> + Index<Col, Output = Vec<F>> + Index<Sel, Output = Vec<F>>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _phantom: self._phantom.clone(),
        }
    }
}

impl<F: Field, W, Col, Sel> FoldableWitness<F, W, Col, Sel>
where
    W: Foldable<F> + Index<Col, Output = Vec<F>> + Index<Sel, Output = Vec<F>>,
{
    pub fn wrap(inner: W) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<F: Field, W, Col, Sel> Foldable<F> for FoldableWitness<F, W, Col, Sel>
where
    W: Foldable<F> + Index<Col, Output = Vec<F>> + Index<Sel, Output = Vec<F>>,
{
    fn combine(a: Self, b: Self, challenge: F) -> Self {
        let inner = W::combine(a.inner, b.inner, challenge);
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<G: CommitmentCurve, W, Col, Sel> instance_witness::Witness<G>
    for FoldableWitness<G::ScalarField, W, Col, Sel>
where
    W: Foldable<G::ScalarField>,
    W: Index<Col, Output = Vec<G::ScalarField>>,
    W: Index<Sel, Output = Vec<G::ScalarField>>,
{
}

pub struct FoldableInstance<G: CommitmentCurve, I, Chall>
where
    I: Foldable<G::ScalarField>,
    I: Index<Chall, Output = G::ScalarField>,
{
    inner: I,
    _phantom: PhantomData<(G, Chall)>,
}

impl<G: CommitmentCurve + Clone, I: Clone, Chall> Clone for FoldableInstance<G, I, Chall>
where
    I: Foldable<G::ScalarField>,
    I: Index<Chall, Output = G::ScalarField>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _phantom: self._phantom.clone(),
        }
    }
}

impl<G: CommitmentCurve, I, Chall> FoldableInstance<G, I, Chall>
where
    I: Instance<G>,
    I: Index<Chall, Output = G::ScalarField>,
{
    pub fn wrap(inner: I) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}
impl<G: CommitmentCurve, I, Chall> Foldable<G::ScalarField> for FoldableInstance<G, I, Chall>
where
    I: Foldable<G::ScalarField>,
    I: Index<Chall, Output = G::ScalarField>,
{
    fn combine(a: Self, b: Self, challenge: G::ScalarField) -> Self {
        let inner = I::combine(a.inner, b.inner, challenge);
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}
impl<G: CommitmentCurve, I, Chall> instance_witness::Instance<G> for FoldableInstance<G, I, Chall>
where
    I: instance_witness::Instance<G>,
    I: Index<Chall, Output = G::ScalarField>,
{
    fn to_absorb(&self) -> (Vec<<G>::ScalarField>, Vec<G>) {
        self.inner.to_absorb()
    }

    fn get_alphas(&self) -> &crate::Alphas<<G>::ScalarField> {
        self.inner.get_alphas()
    }
}

struct StandardConfig<G, Col, Chall, Sel, Str, I, W>(PhantomData<(G, Col, Chall, Sel, Str, I, W)>);

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

impl<G, Col, Chall, Sel, Str, I, W> FoldingConfig for StandardConfig<G, Col, Chall, Sel, Str, I, W>
where
    Self: 'static,
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Foldable<G::ScalarField> + Clone,
    W: Index<Col, Output = Vec<G::ScalarField>> + Index<Sel, Output = Vec<G::ScalarField>>,
    Col: Hash + Eq + Debug + Clone + FoldingColumnTrait,
    Sel: Ord + Copy + Hash + Debug,
    Chall: Hash + Eq + Debug + Copy,
    Str: Clone,
{
    type Column = Col;

    type Selector = Sel;

    type Challenge = Chall;

    type Curve = G;

    type Srs = srs::SRS<G>;

    type Instance = FoldableInstance<G, I, Chall>;

    type Witness = FoldableWitness<G::ScalarField, W, Col, Sel>;

    type Structure = Str;

    type Env = Env<G, Col, Chall, Sel, Str, I, W>;
}
struct Env<G, Col, Chall, Sel, Str, I, W>
where
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Foldable<G::ScalarField> + Clone,
    W: Index<Col, Output = Vec<G::ScalarField>> + Index<Sel, Output = Vec<G::ScalarField>>,
{
    instances: [FoldableInstance<G, I, Chall>; 2],
    witnesses: [FoldableWitness<G::ScalarField, W, Col, Sel>; 2],
    _todo: PhantomData<(Sel, Str)>,
}

impl<G, Col, Chall, Sel, Str, I, W>
    FoldingEnv<
        G::ScalarField,
        FoldableInstance<G, I, Chall>,
        FoldableWitness<G::ScalarField, W, Col, Sel>,
        Col,
        Chall,
        Sel,
    > for Env<G, Col, Chall, Sel, Str, I, W>
where
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Foldable<G::ScalarField> + Clone,
    W: Index<Col, Output = Vec<G::ScalarField>> + Index<Sel, Output = Vec<G::ScalarField>>,
    Col: FoldingColumnTrait,
    Sel: Copy,
{
    type Structure = Str;

    fn new(
        structure: &Self::Structure,
        instances: [&FoldableInstance<G, I, Chall>; 2],
        witnesses: [&FoldableWitness<G::ScalarField, W, Col, Sel>; 2],
    ) -> Self {
        let instances = instances.map(Clone::clone);
        let witnesses = witnesses.map(Clone::clone);
        Self {
            instances,
            witnesses,
            _todo: PhantomData,
        }
    }

    fn challenge(&self, challenge: Chall, side: Side) -> G::ScalarField {
        let instance = match side {
            Side::Left => &self.instances[0],
            Side::Right => &self.instances[1],
        };
        instance.inner[challenge]
    }

    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &Vec<G::ScalarField> {
        //TODO: support Next
        assert!(matches!(curr_or_next, CurrOrNext::Curr));
        let witness = match side {
            Side::Left => &self.witnesses[0],
            Side::Right => &self.witnesses[1],
        };
        if col.is_witness() {
            &witness.inner[col]
        } else {
            //TODO: support structure
            panic!("structure not handled yet")
        }
    }

    fn selector(&self, s: &Sel, side: Side) -> &Vec<G::ScalarField> {
        let witness = match side {
            Side::Left => &self.witnesses[0],
            Side::Right => &self.witnesses[1],
        };
        &witness.inner[*s]
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
    use std::ops::Index;

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

    type MyConfig<G> = StandardConfig<G, MyCol, MyChallenge, (), (), MyInstance<G>, MyWitness<G>>;

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
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
        use mina_poseidon::FqSponge;

        use crate::{
            default_implementation::{FoldableInstance, FoldableWitness},
            FoldingScheme,
        };

        let constraints = vec![constraint()];
        let domain = Radix2EvaluationDomain::<Fp>::new(2).unwrap();
        let mut srs = poly_commitment::srs::SRS::<Curve>::create(2);
        srs.add_lagrange_basis(domain);
        let structure = ();

        let (scheme, _) =
            FoldingScheme::<MyConfig<Curve>>::new(constraints, &srs, domain, &structure);

        let [left, right] = pairs;
        let left = (
            FoldableInstance::wrap(left.0),
            FoldableWitness::wrap(left.1),
        );
        let right = (
            FoldableInstance::wrap(right.0),
            FoldableWitness::wrap(right.1),
        );

        let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());
        // scheme.fold_instance_pair(left, right, error_commitments, fq_sponge);
        scheme.fold_instance_witness_pair(left, right, &mut fq_sponge);
    }
}
