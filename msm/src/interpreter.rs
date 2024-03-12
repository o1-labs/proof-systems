use ark_ff::PrimeField;
use ark_ff::Zero;

use crate::{columns::Column, Fp};

// PRototype-y
pub trait ColIndexer<const COL_N: usize> {
    // TODO: rename it in to_column. It is not necessary to have ix_
    fn ix_to_column(self) -> Column;
    fn flatten_one_level(self) -> usize;
}

pub const FOO_COL_N: usize = 17;

pub enum FooColIndexer {
    Foo1(usize),
    Foo2(usize),
}

pub const BLA_COL_N: usize = 2 * FOO_COL_N + 5;

pub enum BlaColIndexer {
    SubFoo1(FooColIndexer),
    SubFoo2(FooColIndexer),
    Bla1(usize),
    Bla2(usize),
}

impl ColIndexer<FOO_COL_N> for FooColIndexer {
    fn ix_to_column(self) -> Column {
        unimplemented!()
    }
    fn flatten_one_level(self) -> usize {
        unimplemented!()
    }
}

impl ColIndexer<BLA_COL_N> for BlaColIndexer {
    fn ix_to_column(self) -> Column {
        unimplemented!()
    }
    fn flatten_one_level(self) -> usize {
        unimplemented!()
    }
}

// Without integer
pub trait ColFrom0<T: ColIndexer<COL_N>, const COL_N: usize>: Sized {
    // Required method
    fn col_from0(value: T) -> Self;
}

pub trait ColFrom<T: ColIndexer<COL_N>, const COL_N: usize, const N: usize>: Sized {
    // Required method
    fn col_from(value: T) -> Self;
}

impl<CIx: ColIndexer<COL_N>, const COL_N: usize> ColFrom<CIx, COL_N, 0> for CIx {
    fn col_from(v: CIx) -> CIx {
        v
    }
}

impl ColFrom<FooColIndexer, FOO_COL_N, 0> for BlaColIndexer {
    fn col_from(v: FooColIndexer) -> Self {
        BlaColIndexer::SubFoo1(v)
    }
}

impl ColFrom<FooColIndexer, FOO_COL_N, 1> for BlaColIndexer {
    fn col_from(v: FooColIndexer) -> Self {
        BlaColIndexer::SubFoo2(v)
    }
}

// An indexer that behaves like CIxSub, while actually having all the data from CIx.
pub struct SubIndexer<
    const N_COL: usize,
    const SUB_N_COL: usize,
    CIx: ColIndexer<N_COL>,
    CIxSub: ColIndexer<SUB_N_COL>,
> {
    indexer: CIxSub,
    path: Vec<usize>,
    phantom: std::marker::PhantomData<CIx>,
}

impl<
        const N_COL: usize,
        const SUB_N_COL: usize,
        CIx: ColIndexer<N_COL>,
        CIxSub: ColIndexer<SUB_N_COL>,
    > SubIndexer<N_COL, SUB_N_COL, CIx, CIxSub>
{
    pub fn deeper<
        const D: usize,
        const SUB_SUB_N_COL: usize,
        CIxSubSub: ColIndexer<SUB_SUB_N_COL>,
    >(
        self,
        subsub: CIxSubSub,
    ) -> SubIndexer<N_COL, SUB_SUB_N_COL, CIx, CIxSubSub>
    where
        CIxSubSub: ColFrom<CIxSub, SUB_N_COL, D>,
    {
        let SubIndexer { path, phantom, .. } = self;
        let mut newpath: Vec<usize> = path.clone();
        newpath.push(D);
        SubIndexer {
            indexer: subsub,
            path: newpath,
            phantom,
        }
    }
}

//impl<
//        const N_COL: usize,
//        const SUB_N_COL: usize,
//        CIx: ColIndexer<N_COL>,
//        CIxSub: ColIndexer<SUB_N_COL>,
//    > ColFrom0<SubIndexer<N_COL, SUB_N_COL, CIx, CIxSub>, N_COL> for CIx
//{
//    fn col_from(v: SubIndexer<N_COL, SUB_N_COL, CIx, CIxSub>) -> Self {
//        unimplemented!()
//    }
//}

//// SubIndexer for CIxSub is a proper wrapper-indexer on the SUB_N_COL number of columns
//impl<
//        const N_COL: usize,
//        const SUB_N_COL: usize,
//        CIx: ColIndexer<N_COL>,
//        CIxSub: ColIndexer<SUB_N_COL>,
//    > ColIndexer<SUB_N_COL> for SubIndexer<N_COL, SUB_N_COL, CIx, CIxSub>
//{
//    fn ix_to_column(self) -> Column {
//        self.indexer.ix_to_column()
//    }
//}

// SubIndexer for CIxSub is a proper wrapper-indexer on the N_COL number of columns
impl<
        const N_COL: usize,
        const SUB_N_COL: usize,
        CIx: ColIndexer<N_COL>,
        CIxSub: ColIndexer<SUB_N_COL>,
    > ColIndexer<N_COL> for SubIndexer<N_COL, SUB_N_COL, CIx, CIxSub>
{
    fn ix_to_column(self) -> Column {
        self.indexer.ix_to_column()
    }
}

/// Attempt to define a generic interpreter.
/// It is not used yet.
pub trait InterpreterEnv<const COL_N: usize, CIx: ColIndexer<COL_N>, Fp: PrimeField> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn assert_zero(&mut self, cst: Self::Variable);

    /// Copy the value in the position `ix`
    fn copy(&mut self, x: &Self::Variable, ix: CIx) -> Self::Variable;

    /// Read the value in the position `ix`
    fn read_column(&self, ix: CIx) -> Self::Variable;

    fn constant(value: Fp) -> Self::Variable;

    //    fn to_sub<const COL_M: usize, SubCIx: ColIndexer<COL_M>>(
    //        &self,
    //    ) -> dyn InterpreterEnv<COL_M, SubCIx, Fp, Variable = Self::Variable>;
}

/// Reads values from limbs A and B, returns resulting value in C.
pub fn constrain_multiplication<F, CIx, const N: usize, const COL_N: usize, Env>(
    env: &mut Env,
) -> Env::Variable
where
    F: PrimeField,
    CIx: ColFrom<FooColIndexer, FOO_COL_N, N> + ColIndexer<COL_N>,
    Env: InterpreterEnv<COL_N, CIx, F>,
{
    let _a_var: Env::Variable = Env::read_column(env, CIx::col_from(FooColIndexer::Foo1(0)));
    unimplemented!()
}

pub fn constrain_bla<F, CIx, const N: usize, const COL_N: usize, Env>(
    env: &mut Env,
) -> Env::Variable
where
    F: PrimeField,
    CIx: ColFrom<BlaColIndexer, BLA_COL_N, N>
        + ColFrom<FooColIndexer, FOO_COL_N, 0> // TODO automatic instances?
        + ColIndexer<COL_N>,
    Env: InterpreterEnv<COL_N, CIx, F>,
{
    constrain_multiplication::<F, CIx, 0, COL_N, Env>(env);
    unimplemented!()
}

//pub fn test_multiplication<F: PrimeField, Env: InterpreterEnv<F>>(env: &mut Env, a: Ff1) {
//    let _ = constrain_multiplication(env); // we don't do anything else further with c_limbs
//    unimplemented!()
//}

#[allow(dead_code)]
/// Builder environment for a native group `G`.
pub struct WitnessBuilderEnv<F: PrimeField, const COL_N: usize> {
    /// Aggregated witness, in raw form. For accessing [`Witness`], see the
    /// `get_witness` method.
    witness: [F; COL_N],
}

impl<F: PrimeField, const COL_N: usize, CIx: ColIndexer<COL_N>> InterpreterEnv<COL_N, CIx, F>
    for WitnessBuilderEnv<F, COL_N>
{
    type Variable = F;

    fn assert_zero(&mut self, cst: Self::Variable) {
        assert_eq!(cst, F::zero());
    }

    fn constant(value: F) -> Self::Variable {
        value
    }

    fn copy(&mut self, value: &Self::Variable, ix: CIx) -> Self::Variable {
        let Column::X(i) = ix.ix_to_column();
        self.witness[i] = *value;
        *value
    }

    fn read_column(&self, ix: CIx) -> Self::Variable {
        let Column::X(i) = ix.ix_to_column();
        self.witness[i]
    }
}

impl<const COL_N: usize> WitnessBuilderEnv<Fp, COL_N> {
    fn _empty() -> Self {
        WitnessBuilderEnv {
            witness: [Zero::zero(); COL_N],
        }
    }

    //    /// Each WitnessColumn stands for both one row and multirow. This
    //    /// function converts from a vector of one-row instantiation to a
    //    /// single multi-row form (which is a `Witness`).
    //    pub fn get_witness(
    //        &self,
    //        domain_size: usize,
    //    ) -> ProofInputs<COL_N, BN254G1Affine, LookupTableIDs> {
    //        let mut cols: [Vec<Fp>; COL_N] = std::array::from_fn(|_| vec![]);
    //
    //        if self.witness.len() > domain_size {
    //            panic!("Too many witness rows added");
    //        }
    //
    //        // Filling actually used rows
    //        for w in &self.witness {
    //            let Witness { cols: witness_row } = w;
    //            for i in 0..COL_N {
    //                cols[i].push(witness_row[i]);
    //            }
    //        }
    //
    //        // Filling ther rows up to the domain size
    //        for _ in self.witness.len()..domain_size {
    //            for col in cols.iter_mut() {
    //                col.push(Zero::zero());
    //            }
    //        }
    //
    //        ProofInputs {
    //            evaluations: Witness { cols },
    //            mvlookups: vec![],
    //            public_input_size: 0,
    //        }
    //    }
}
