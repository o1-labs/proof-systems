//! A kind of pseudo-prover, will compute the expressions over the witness a check row by row
//! for a zero result.

use crate::{
    expressions::{FoldingColumnTrait, FoldingCompatibleExpr, FoldingCompatibleExprInner},
    instance_witness::Instance,
    ExpExtension, FoldingConfig, Radix2EvaluationDomain, RelaxedInstance, RelaxedWitness,
};
use ark_ec::{AdditiveGroup, AffineRepr};
use ark_ff::{Field, Zero};
use ark_poly::Evaluations;
use core::ops::Index;
use kimchi::circuits::{expr::Variable, gate::CurrOrNext};

#[cfg(not(test))]
use log::debug;
#[cfg(test)]
use std::println as debug;

// 1. We continue by defining a generic type of columns and selectors.
// The selectors can be seen as additional (public) columns that are not part of
// the witness.
// The column must implement the trait [Hash] as it will be used by internal
// structures of the library.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Column {
    X(usize),
    Selector(usize),
}

// 2. We implement the trait [FoldingColumnTrait] that allows to distinguish
// between the public and private inputs, often called the "instances" and the
// "witnesses".
// By default, we consider that the columns are all witness values and selectors
// are public.
impl FoldingColumnTrait for Column {
    fn is_witness(&self) -> bool {
        match self {
            Column::X(_) => true,
            Column::Selector(_) => false,
        }
    }
}

// 3. We define different traits that can be used generically by the folding
// examples.
// It can be used by "pseudo-provers".

pub struct Provider<C: FoldingConfig> {
    pub instance: C::Instance,
    pub witness: C::Witness,
}

impl<C: FoldingConfig> Provider<C> {
    pub fn new(instance: C::Instance, witness: C::Witness) -> Self {
        Self { instance, witness }
    }
}

pub struct ExtendedProvider<C: FoldingConfig> {
    pub inner_provider: Provider<C>,
    pub instance: RelaxedInstance<<C as FoldingConfig>::Curve, <C as FoldingConfig>::Instance>,
    pub witness: RelaxedWitness<<C as FoldingConfig>::Curve, <C as FoldingConfig>::Witness>,
}

impl<C: FoldingConfig> ExtendedProvider<C> {
    pub fn new(
        instance: RelaxedInstance<C::Curve, C::Instance>,
        witness: RelaxedWitness<C::Curve, C::Witness>,
    ) -> Self {
        let inner_provider = {
            let instance = instance.extended_instance.instance.clone();
            let witness = witness.extended_witness.witness.clone();
            Provider::new(instance, witness)
        };
        Self {
            inner_provider,
            instance,
            witness,
        }
    }
}

pub trait Provide<C: FoldingConfig> {
    fn resolve(
        &self,
        inner: FoldingCompatibleExprInner<C>,
        domain: Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
    ) -> Vec<<C::Curve as AffineRepr>::ScalarField>;
}

impl<C: FoldingConfig> Provide<C> for Provider<C>
where
    C::Witness: Index<
        C::Column,
        Output = Evaluations<
            <C::Curve as AffineRepr>::ScalarField,
            Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
        >,
    >,
    C::Witness: Index<
        C::Selector,
        Output = Evaluations<
            <C::Curve as AffineRepr>::ScalarField,
            Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
        >,
    >,
    C::Instance: Index<C::Challenge, Output = <C::Curve as AffineRepr>::ScalarField>,
{
    fn resolve(
        &self,
        inner: FoldingCompatibleExprInner<C>,
        domain: Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
    ) -> Vec<<C::Curve as AffineRepr>::ScalarField> {
        let domain_size = domain.size as usize;
        match inner {
            FoldingCompatibleExprInner::Constant(c) => {
                vec![c; domain_size]
            }
            FoldingCompatibleExprInner::Challenge(chal) => {
                let v = self.instance[chal];
                vec![v; domain_size]
            }
            FoldingCompatibleExprInner::Cell(var) => {
                let Variable { col, row } = var;

                let col = &self.witness[col].evals;

                let mut col = col.clone();
                //check this, while not relevant in this case I think it should be right rotation
                if let CurrOrNext::Next = row {
                    col.rotate_left(1);
                }
                col
            }
            FoldingCompatibleExprInner::Extensions(_) => {
                panic!("not handled here");
            }
        }
    }
}

impl<C: FoldingConfig> Provide<C> for ExtendedProvider<C>
where
    C::Witness: Index<
        C::Column,
        Output = Evaluations<
            <C::Curve as AffineRepr>::ScalarField,
            Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
        >,
    >,
    C::Witness: Index<
        C::Selector,
        Output = Evaluations<
            <C::Curve as AffineRepr>::ScalarField,
            Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
        >,
    >,
    C::Instance: Index<C::Challenge, Output = <C::Curve as AffineRepr>::ScalarField>,
{
    fn resolve(
        &self,
        inner: FoldingCompatibleExprInner<C>,
        domain: Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
    ) -> Vec<<C::Curve as AffineRepr>::ScalarField> {
        match inner {
            FoldingCompatibleExprInner::Extensions(ext) => match ext {
                ExpExtension::U => {
                    let u = self.instance.u;
                    let domain_size = domain.size as usize;
                    vec![u; domain_size]
                }
                ExpExtension::Error => self.witness.error_vec.evals.clone(),
                ExpExtension::ExtendedWitness(i) => self
                    .witness
                    .extended_witness
                    .extended
                    .get(&i)
                    .unwrap()
                    .evals
                    .clone(),
                ExpExtension::Alpha(i) => {
                    let alpha = self
                        .instance
                        .extended_instance
                        .instance
                        .get_alphas()
                        .get(i)
                        .unwrap();
                    let domain_size = domain.size as usize;
                    vec![alpha; domain_size]
                }
                ExpExtension::Selector(s) => {
                    let col = &self.inner_provider.witness[s].evals;
                    col.clone()
                }
            },
            e => self.inner_provider.resolve(e, domain),
        }
    }
}

pub trait Checker<C: FoldingConfig>: Provide<C> {
    fn check_rec(
        &self,
        exp: FoldingCompatibleExpr<C>,
        domain: Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
    ) -> Vec<<C::Curve as AffineRepr>::ScalarField> {
        let e2 = exp.clone();
        let res = match exp {
            FoldingCompatibleExpr::Atom(inner) => self.resolve(inner, domain),
            FoldingCompatibleExpr::Double(e) => {
                let v = self.check_rec(*e, domain);
                v.into_iter().map(|x| x.double()).collect()
            }
            FoldingCompatibleExpr::Square(e) => {
                let v = self.check_rec(*e, domain);
                v.into_iter().map(|x| x.square()).collect()
            }
            FoldingCompatibleExpr::Add(e1, e2) => {
                let v1 = self.check_rec(*e1, domain);
                let v2 = self.check_rec(*e2, domain);
                v1.into_iter().zip(v2).map(|(a, b)| a + b).collect()
            }
            FoldingCompatibleExpr::Sub(e1, e2) => {
                let v1 = self.check_rec(*e1, domain);
                let v2 = self.check_rec(*e2, domain);
                v1.into_iter().zip(v2).map(|(a, b)| a - b).collect()
            }
            FoldingCompatibleExpr::Mul(e1, e2) => {
                let v1 = self.check_rec(*e1, domain);
                let v2 = self.check_rec(*e2, domain);
                v1.into_iter().zip(v2).map(|(a, b)| a * b).collect()
            }
            FoldingCompatibleExpr::Pow(e, exp) => {
                let v = self.check_rec(*e, domain);
                v.into_iter().map(|x| x.pow([exp])).collect()
            }
        };
        debug!("exp: {:?}", e2);
        debug!("res: [\n");
        for e in res.iter() {
            debug!("{e}\n");
        }
        debug!("]");
        res
    }

    fn check(
        &self,
        exp: &FoldingCompatibleExpr<C>,
        domain: Radix2EvaluationDomain<<C::Curve as AffineRepr>::ScalarField>,
    ) {
        let res = self.check_rec(exp.clone(), domain);
        for (i, row) in res.iter().enumerate() {
            if !row.is_zero() {
                panic!("check in row {i} failed, {row} != 0");
            }
        }
    }
}
