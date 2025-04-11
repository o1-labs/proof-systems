//! This module offers a standard implementation of [FoldingConfig] supporting
//! many use cases
use crate::{
    expressions::FoldingColumnTrait, instance_witness::Witness, FoldingConfig, FoldingEnv,
    Instance, Side,
};
use core::{fmt::Debug, hash::Hash, marker::PhantomData, ops::Index};
use derivative::Derivative;
use kimchi::{circuits::gate::CurrOrNext, curve::KimchiCurve};
use memoization::ColumnMemoizer;
use poly_commitment::{self, commitment::CommitmentCurve};

#[derive(Clone, Default)]
/// Default type for when you don't need structure
pub struct EmptyStructure<G: KimchiCurve>(PhantomData<G::ScalarField>);

impl<G: KimchiCurve, Col> Index<Col> for EmptyStructure<G> {
    type Output = Vec<G::ScalarField>;

    fn index(&self, _index: Col) -> &Self::Output {
        panic!("shouldn't reach this point, as this type only works with witness-only constraint systems");
    }
}

/// A standard folding config that supports:
/// `G`: any curve
/// `Col`: any column implementing [FoldingColumnTrait]
/// `Chall`: any challenge
/// `Sel`: any dynamic selector
/// `Str`: structures that can be indexed by `Col`, thus implementing `Index<Col>`
/// `I`: instances (implementing [Instance]) that can be indexed by `Chall`
/// `W`: witnesses (implementing [Witness]) that can be indexed by `Col` and `Sel`
/// ```ignore
/// use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
/// use mina_poseidon::FqSponge;
/// use folding::{examples::{BaseSponge, Curve, Fp}, FoldingScheme};
///
/// // instantiating the config with our types and the defaults for selectors and structure
/// type MyConfig = StandardConfig<Curve, MyCol, MyChallenge, MyInstance<Curve>, MyWitness<Curve>>;
/// let constraints = vec![constraint()];
/// let domain = Radix2EvaluationDomain::<Fp>::new(2).unwrap();
/// let srs = poly_commitment::srs::SRS::<Curve>::create(2);
/// srs.get_lagrange_basis(domain);
/// // this is the default structure, which does nothing or panics if
/// // indexed (as it shouldn't be indexed)
/// let structure = EmptyStructure::default();
///
/// // here we can use the config
/// let (scheme, _) =
/// FoldingScheme::<MyConfig>::new(constraints, &srs, domain, &structure);
///
/// let [left, right] = pairs;
/// let left = (left.0, left.1);
/// let right = (right.0, right.1);
///
/// let mut fq_sponge = BaseSponge::new(Curve::other_curve_sponge_params());
/// let _output = scheme.fold_instance_witness_pair(left, right, &mut fq_sponge);
/// ```
#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq, Debug)]
#[allow(clippy::type_complexity)]
pub struct StandardConfig<G, Col, Chall, I, W, Srs, Sel = (), Str = EmptyStructure<G>>(
    PhantomData<(G, Col, Chall, Sel, Str, I, W, Srs)>,
);

//implementing FoldingConfig
impl<G, Col, Chall, Sel, Str, I, W, Srs> FoldingConfig
    for StandardConfig<G, Col, Chall, I, W, Srs, Sel, Str>
where
    Self: 'static,
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Witness<G> + Clone,
    W: Index<Col, Output = [G::ScalarField]> + Index<Sel, Output = [G::ScalarField]>,
    Srs: poly_commitment::SRS<G>,
    Col: Hash + Eq + Debug + Clone + FoldingColumnTrait,
    Sel: Ord + Copy + Hash + Debug,
    Chall: Hash + Eq + Debug + Copy,
    Str: Clone + Index<Col, Output = [G::ScalarField]>,
{
    type Column = Col;

    type Selector = Sel;

    type Challenge = Chall;

    type Curve = G;

    type Srs = Srs;

    type Instance = I;

    type Witness = W;

    type Structure = Str;

    type Env = Env<G, Col, Chall, Sel, Str, I, W>;
}
///A generic Index based environment
pub struct Env<G, Col, Chall, Sel, Str, I, W>
where
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Witness<G> + Clone,
    W: Index<Col, Output = [G::ScalarField]> + Index<Sel, Output = [G::ScalarField]>,
    Col: Hash + Eq,
{
    instances: [I; 2],
    witnesses: [W; 2],
    next_evals: ColumnMemoizer<Col, G::ScalarField, 10>,
    structure: Str,
    //not used but needed as generics for the bounds
    _phantom: PhantomData<(G, Col, Chall, Sel, Str)>,
}

//implementing FoldingEnv
impl<G, Col, Chall, Sel, Str, I, W> FoldingEnv<G::ScalarField, I, W, Col, Chall, Sel>
    for Env<G, Col, Chall, Sel, Str, I, W>
where
    G: CommitmentCurve,
    I: Instance<G> + Index<Chall, Output = G::ScalarField> + Clone,
    W: Witness<G> + Clone,
    W: Index<Col, Output = [G::ScalarField]> + Index<Sel, Output = [G::ScalarField]>,
    Col: FoldingColumnTrait + Eq + Hash,
    Sel: Copy,
    Str: Clone + Index<Col, Output = [G::ScalarField]>,
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
            next_evals: ColumnMemoizer::new(),
            _phantom: PhantomData,
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

    fn col(&self, col: Col, curr_or_next: CurrOrNext, side: Side) -> &[G::ScalarField] {
        let witness = match side {
            Side::Left => &self.witnesses[0],
            Side::Right => &self.witnesses[1],
        };
        // this should hold as long the Index implementations are consistent with the
        // FoldingColumnTrait implementation.
        // either search in witness for witness columns, or in the structure otherwise
        if col.is_witness() {
            match curr_or_next {
                CurrOrNext::Curr => &witness[col],
                CurrOrNext::Next => {
                    let f = || {
                        // simple but not the best, ideally there would be a single vector,
                        // where you push its first element and offer either evals[0..] or
                        // evals[1..].
                        // that would relatively easy to implement in a custom implementation
                        // with just a small change to this trait, but in this generic implementation
                        // it is harder to implement.
                        // The cost is mostly the cost of a clone
                        let evals = &witness[col];
                        let mut next = Vec::with_capacity(evals.len());
                        next.extend(evals[1..].iter());
                        next.push(evals[0]);
                        next
                    };
                    self.next_evals.get_or_insert(col, f)
                }
            }
        } else {
            &self.structure[col]
        }
    }

    fn selector(&self, s: &Sel, side: Side) -> &[G::ScalarField] {
        //similar to the witness case of col, as expected
        let witness = match side {
            Side::Left => &self.witnesses[0],
            Side::Right => &self.witnesses[1],
        };
        &witness[*s]
    }
}

/// contains a data structure useful to support the [CurrOrNext::Next] case
/// in [FoldingEnv::col]
mod memoization {
    use ark_ff::Field;
    use core::hash::Hash;
    use std::{
        cell::{OnceCell, RefCell},
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// a segment with up to N stored columns, and the potential
    /// next segment, similar to a linked list N-length arrays
    pub struct ColumnMemoizerSegment<F: Field, const N: usize> {
        cols: [OnceCell<Vec<F>>; N],
        next: OnceCell<Box<Self>>,
    }

    impl<F: Field, const N: usize> ColumnMemoizerSegment<F, N> {
        pub fn new() -> Self {
            let cols = [(); N].map(|_| OnceCell::new());
            let next = OnceCell::new();
            Self { cols, next }
        }
        // This will find the column if i < N, and get a reference to it,
        // initializing it with `f` if needed.
        // If i >= N it will continue recursing to the next segment, initializing
        // it if needed
        pub fn get_or_insert<I>(&self, i: usize, f: I) -> &Vec<F>
        where
            I: FnOnce() -> Vec<F>,
        {
            match i {
                i if i < N => {
                    let col = &self.cols[i];
                    col.get_or_init(f)
                }
                i => {
                    let i = i - N;
                    let new = || Box::new(Self::new());
                    let next = self.next.get_or_init(new);
                    next.get_or_insert(i, f)
                }
            }
        }
    }
    /// a hashmap like data structure supporting get-or-insert with
    /// an immutable reference and returning an immutable reference
    /// without guard
    pub struct ColumnMemoizer<C: Hash + Eq, F: Field, const N: usize> {
        first_segment: ColumnMemoizerSegment<F, N>,
        next: AtomicUsize,
        ids: RefCell<HashMap<C, usize>>,
    }

    impl<C: Hash + Eq, F: Field, const N: usize> ColumnMemoizer<C, F, N> {
        pub fn new() -> Self {
            let first_segment = ColumnMemoizerSegment::new();
            let next = AtomicUsize::from(0);
            let ids = RefCell::new(HashMap::new());
            Self {
                first_segment,
                next,
                ids,
            }
        }
        pub fn get_or_insert<I>(&self, col: C, f: I) -> &Vec<F>
        where
            I: FnOnce() -> Vec<F>,
        {
            // this will find or assign an id for the column and then
            // search the segments using the id
            let mut ids = self.ids.borrow_mut();
            let new_id = || self.next.fetch_add(1, Ordering::Relaxed);
            let id = ids.entry(col).or_insert_with(new_id);
            self.first_segment.get_or_insert(*id, f)
        }
    }
}
