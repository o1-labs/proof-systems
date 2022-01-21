//! This module implements an abstraction to keep track of the powers of alphas.
//! As a recap, alpha is a challenge sent by the verifier in PLONK,
//! and is used to segregate different constraints.
//! It is important that different constraints use different powers of alpha,
//! as otherwise they can interact and potentially cancel one another.
//! (The proof is in the use of the Schwartz-Zipple lemma.)
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
//! Both construction will enforce that you use all the powers of
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
#[derive(PartialEq, Eq, Clone, Hash, Debug, Serialize, Deserialize)]
pub enum ConstraintType {
    /// gates in the PLONK constraint system.
    /// As gates are mutually exclusive (only a single selector polynomial
    /// will be non-zero for a given point),
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
#[cfg_attr(feature = "ocaml_types", derive(ocaml_gen::CustomType))]
pub struct Builder {
    /// The next power of alpha to use
    next_power: usize,
    /// The mapping between constraint types and powers of alpha
    mapping: HashMap<ConstraintType, Range<usize>>,
}

impl Builder {
    /// Registers a new [ConstraintType],
    /// associating it a number `powers` of powers of alpha.
    /// The function returns an iterator of powers that must be used.
    #[must_use]
    pub fn register(&mut self, ty: ConstraintType, powers: usize) -> Range<usize> {
        let new_power = self.next_power + powers;
        let range = self.next_power..new_power;
        if self.mapping.insert(ty.clone(), range.clone()).is_some() {
            panic!("you are attempting to register {:?} twice", ty);
        }
        self.next_power = new_power;
        range
    }

    /// Creates a new instance of [Alphas] via a [Builder] and value `alpha`.
    pub fn into_alphas<F: Field>(self, alpha: F) -> Alphas<F> {
        let mut last_power = F::one();
        let mut alphas = Vec::with_capacity(self.next_power);
        alphas.push(F::one());
        for _ in 0..self.next_power {
            last_power *= alpha;
            alphas.push(last_power);
        }

        Alphas {
            alphas,
            mapping: self.mapping,
        }
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
    #[must_use]
    pub fn new(alpha: F, powers: &Builder) -> Alphas<F> {
        let mut last_power = F::one();
        let mut alphas = Vec::with_capacity(powers.next_power);
        alphas.push(F::one());
        for _ in 0..powers.next_power {
            last_power *= alpha;
            alphas.push(last_power);
        }

        Alphas {
            alphas,
            mapping: powers.mapping.clone(),
        }
    }

    /// This returns a range of powers (the exponents), upperbounded by `num`
    #[must_use]
    pub fn get_powers(
        &mut self,
        ty: ConstraintType,
        num: usize,
    ) -> MustConsumeIterator<Take<Range<usize>>, usize> {
        let range = self
            .mapping
            .get(&ty)
            .unwrap_or_else(|| panic!("you attempted to retrieve powers of the constraint {:?} when it has either not been registered or already been retrieved once", ty));
        MustConsumeIterator(range.clone().take(num), ty)
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
            .unwrap_or_else(|| panic!("you attempted to retrieve powers of alphas of the constraint {:?} when it has either not been registered or already been retrieved once", ty));
        let alphas = self.alphas[range.clone()].iter().take(num).cloned();
        MustConsumeIterator(alphas, ty)
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
pub struct MustConsumeIterator<I, T>(I, ConstraintType)
where
    I: Iterator<Item = T>,
    T: std::fmt::Display;

impl<I, T> Iterator for MustConsumeIterator<I, T>
where
    I: Iterator<Item = T>,
    T: std::fmt::Display,
{
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<I, T> Drop for MustConsumeIterator<I, T>
where
    I: Iterator<Item = T>,
    T: std::fmt::Display,
{
    fn drop(&mut self) {
        if let Some(v) = self.0.next() {
            if thread::panicking() {
                eprintln!("the registered number of powers of alpha for {:?} is too large, you haven't used alpha^{} (absolute power of alpha)", self.1,
                v);
            } else {
                panic!("the registered number of powers of alpha for {:?} is too large, you haven't used alpha^{} (absolute power of alpha)", self.1,
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

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;

    impl Builder {
        extern "C" fn finalize(v: ocaml::Raw) {
            unsafe {
                let mut v: ocaml::Pointer<Self> = v.as_pointer();
                v.as_mut_ptr().drop_in_place();
            }
        }
    }

    ocaml::custom!(Builder {
        finalize: Builder::finalize,
    });

    unsafe impl<'a> ::ocaml::FromValue<'a> for Builder {
        fn from_value(value: ::ocaml::Value) -> Self {
            let x: ::ocaml::Pointer<Self> = ::ocaml::FromValue::from_value(value);
            x.as_ref().clone()
        }
    }
}
