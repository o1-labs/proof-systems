//! This module implements an abstraction to keep track of the powers of alphas.
//! As a recap, alpha is a challenge sent by the verifier in PLONK,
//! and is used to aggregate multiple constraints into a single polynomial.
//! It is important that different constraints use different powers of alpha,
//! as otherwise they can interact and potentially cancel one another.
//! (The proof is in the use of the Schwartz-Zippel lemma.)
//! As such, we want two properties from this:
//!
//! - we should keep track of a mapping between type of constraint and range of powers
//! - when powers of alphas are used, we should ensure that no more no less are used
//!
//! We use powers of alpha in two different places in the codebase:
//!
//! - when creating the index, we do not know alpha at this point so we
//!   simply keep track of what constraints will use what powers
//! - when creating a proof or verifying a proof, at this point we know alpha
//!   so we can use the mapping we created during the creation of the index.
//!
//! For this to work, we use two types:
//!
//! - [Builder], which allows us to map constraints to powers
//! - [Alphas], which you can derive from [Builder] and an `alpha`
//!
//! Both constructions will enforce that you use all the powers of
//! alphas that you register for constraint. This allows us to
//! make sure that we compute the correct amounts, without reusing
//! powers of alphas between constraints.

use ark_ff::Field;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    iter::{Cloned, Take},
    ops::Range,
    slice::Iter,
    thread,
};

// ------------------------------------------

/// A constraint type represents a polynomial that will be part of the final equation f (the circuit equation)
#[derive(PartialEq, Eq, Clone, Copy, Hash, Debug, Serialize, Deserialize)]
pub enum ConstraintType {
    /// gates in the PLONK constraint system.
    /// As gates are mutually exclusive (only a single selector polynomial
    /// will be non-zero for a given row),
    /// we can reuse the same power of alphas accross gates.
    Gate,
    /// The permutation argument
    Permutation,
    /// The lookup argument
    Lookup,
}

// ------------------------------------------

/// This type can be used to create a mapping between powers of alpha and constraint types.
/// See [Builder::default] to create one,
/// and [Builder::register] to register a new mapping.
/// Once you know the alpha value, you can convert this type to a [Alphas].
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Builder {
    /// The next power of alpha to use
    /// the end result will be [1, alpha^next_power)    
    next_power: usize,
    /// The mapping between constraint types and powers of alpha
    mapping: HashMap<ConstraintType, Range<usize>>,
}

impl Builder {
    /// Registers a new [ConstraintType],
    /// associating it with a number `powers` of powers of alpha.
    /// The function returns an iterator of powers that haven't been used yet.
    pub fn register(&mut self, ty: ConstraintType, powers: usize) -> Range<usize> {
        let new_power = self.next_power + powers;
        let range = self.next_power..new_power;
        if self.mapping.insert(ty, range.clone()).is_some() {
            panic!("cannot re-register {:?}", ty);
        }
        self.next_power = new_power;
        range
    }
}

// ------------------------------------------

/// This type can be constructed from [Builder] and a value `alpha`,
/// via [Alphas::new].
/// It will then pre-compute the necessary numbers of powers of alpha.
/// You can retrieve powers of alpha by calling [Alphas::take_alphas],
/// or the exponents without the actual powers of alphas via [Alphas::take_powers].
pub struct Alphas<F> {
    /// The powers of alpha: 1, alpha, alpha^2, etc.
    alphas: Vec<F>,
    /// The mapping from constraint type to a range of powers of alpha
    mapping: HashMap<ConstraintType, Range<usize>>,
}

impl<F: Field> Alphas<F> {
    /// Creates a new instance of [Alphas] via a [Builder] and value `alpha`.
    pub fn new(alpha: F, powers: &Builder) -> Alphas<F> {
        let mut last_power = F::one();
        let mut alphas = Vec::with_capacity(powers.next_power);
        alphas.push(F::one());
        for _ in 0..(powers.next_power - 1) {
            last_power *= alpha;
            alphas.push(last_power);
        }

        Alphas {
            alphas,
            mapping: powers.mapping.clone(),
        }
    }

    /// This returns a range of powers (the exponents), upperbounded by `num`
    pub fn get_powers(
        &mut self,
        ty: ConstraintType,
        num: usize,
    ) -> MustConsumeIterator<Take<Range<usize>>, usize> {
        let range = self
            .mapping
            .get(&ty)
            .unwrap_or_else(|| panic!("constraint {:?} was not registered", ty));
        MustConsumeIterator {
            inner: range.clone().take(num),
            debug_info: ty,
        }
    }

    /// This function allows us to retrieve the powers of alpha, upperbounded by `num`
    pub fn get_alphas(
        &self,
        ty: ConstraintType,
        num: usize,
    ) -> MustConsumeIterator<Cloned<Take<Iter<F>>>, F> {
        let range = self
            .mapping
            .get(&ty)
            .unwrap_or_else(|| panic!("constraint {:?} was not registered", ty));
        let alphas = self.alphas[range.clone()].iter().take(num).cloned();
        MustConsumeIterator {
            inner: alphas,
            debug_info: ty,
        }
    }

    /// As the new expression framework does not make use of pre-computed
    /// powers of alphas, we need to discard some of the pre-computed powers
    /// via this function (otherwise you will get a warning).
    pub fn discard(&mut self, ty: ConstraintType) {
        self.mapping.remove(&ty);
    }
}

// ------------------------------------------

/// Wrapper around an iterator that warns you if not consumed entirely.
#[derive(Debug)]
pub struct MustConsumeIterator<I, T>
where
    I: Iterator<Item = T>,
    T: std::fmt::Display,
{
    inner: I,
    debug_info: ConstraintType,
}

impl<I, T> Iterator for MustConsumeIterator<I, T>
where
    I: Iterator<Item = T>,
    T: std::fmt::Display,
{
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<I, T> Drop for MustConsumeIterator<I, T>
where
    I: Iterator<Item = T>,
    T: std::fmt::Display,
{
    fn drop(&mut self) {
        if let Some(v) = self.inner.next() {
            if thread::panicking() {
                eprintln!("the registered number of powers of alpha for {:?} is too large, you haven't used alpha^{} (absolute power of alpha)", self.debug_info,
                v);
            } else {
                panic!("the registered number of powers of alpha for {:?} is too large, you haven't used alpha^{} (absolute power of alpha)", self.debug_info,
                v);
            }
        }
    }
}

// ------------------------------------------

#[cfg(test)]
mod tests {
    use mina_curves::pasta::Fp;

    use super::*;

    // testing [Builder]

    #[test]
    fn incorrect_alpha_powers() {
        let mut builder = Builder::default();
        let mut powers = builder.register(ConstraintType::Gate, 3);

        assert_eq!(powers.next(), Some(0));
        assert_eq!(powers.next(), Some(1));
        assert_eq!(powers.next(), Some(2));

        let mut powers = builder.register(ConstraintType::Permutation, 3);

        assert_eq!(powers.next(), Some(3));
        assert_eq!(powers.next(), Some(4));
        assert_eq!(powers.next(), Some(5));
    }

    #[test]
    #[should_panic]
    fn didnt_use_all_alpha_powers() {
        let mut builder = Builder::default();
        let mut powers = builder.register(ConstraintType::Permutation, 7);

        powers.next();

        let mut powers = builder.register(ConstraintType::Permutation, 3);
        powers.next();
        powers.next();
        powers.next();
    }

    #[test]
    #[should_panic]
    fn registered_alpha_powers_for_some_constraint_twice() {
        let mut builder = Builder::default();
        let _ = builder.register(ConstraintType::Gate, 2);
        let _ = builder.register(ConstraintType::Gate, 3);
    }

    // testing [Alphas]

    #[test]
    fn powers_of_alpha() {
        let mut builder = Builder::default();
        let mut powers = builder.register(ConstraintType::Gate, 4);

        assert_eq!(powers.next(), Some(0));
        assert_eq!(powers.next(), Some(1));
        assert_eq!(powers.next(), Some(2));
        assert_eq!(powers.next(), Some(3));

        let alpha = Fp::from(2);
        let all_alphas = Alphas::new(alpha, &builder);

        let mut alphas = all_alphas.get_alphas(ConstraintType::Gate, 4);
        assert_eq!(alphas.next(), Some(1.into()));
        assert_eq!(alphas.next(), Some(2.into()));
        assert_eq!(alphas.next(), Some(4.into()));
        assert_eq!(alphas.next(), Some(8.into()));
    }
}
