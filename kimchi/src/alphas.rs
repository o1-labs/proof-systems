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
//! For this to work, we use the type [Alphas] to register ranges of powers of alpha,
//! for the various [ArgumentType]s.
//!

use crate::circuits::{argument::ArgumentType, gate::GateType};
use ark_ff::Field;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    iter::{Cloned, Skip, Take},
    ops::Range,
    slice::Iter,
    thread,
};

// ------------------------------------------

/// This type can be used to create a mapping between powers of alpha and constraint types.
/// See [Self::default] to create one,
/// and [Self::register] to register a new mapping.
/// Once you know the alpha value, you can convert this type to a [Alphas].
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Alphas<F> {
    /// The next power of alpha to use
    /// the end result will be [1, alpha^{next_power - 1}]
    next_power: u32,
    /// The mapping between constraint types and powers of alpha
    mapping: HashMap<ArgumentType, (u32, u32)>,
    /// The powers of alpha: 1, alpha, alpha^2, etc.
    /// If set to [Some], you can't register new constraints.
    alphas: Option<Vec<F>>,
}

impl<F: Field> Alphas<F> {
    /// Registers a new [ArgumentType],
    /// associating it with a number `powers` of powers of alpha.
    /// This function will panic if you register the same type twice.
    pub fn register(&mut self, ty: ArgumentType, powers: u32) {
        if self.alphas.is_some() {
            panic!("you cannot register new constraints once initialized with a field element");
        }

        // gates are a special case, as we reuse the same power of alpha
        // across all of them (they're mutually exclusive)
        let ty = if matches!(ty, ArgumentType::Gate(_)) {
            // the zero gate is not used, so we default to it
            ArgumentType::Gate(GateType::Zero)
        } else {
            ty
        };

        if self.mapping.insert(ty, (self.next_power, powers)).is_some() {
            panic!("cannot re-register {:?}", ty);
        }

        self.next_power = self
            .next_power
            .checked_add(powers)
            .expect("too many powers of alphas were registered");
    }

    /// Returns a range of exponents, for a given [ArgumentType], upperbounded by `num`.
    /// Note that this function will panic if you did not register enough powers of alpha.
    pub fn get_exponents(
        &self,
        ty: ArgumentType,
        num: u32,
    ) -> MustConsumeIterator<Range<u32>, u32> {
        let ty = if matches!(ty, ArgumentType::Gate(_)) {
            ArgumentType::Gate(GateType::Zero)
        } else {
            ty
        };

        let range = self
            .mapping
            .get(&ty)
            .unwrap_or_else(|| panic!("constraint {:?} was not registered", ty));

        if num > range.1 {
            panic!(
                "you asked for {num} exponents, but only registered {} for {:?}",
                range.1, ty
            );
        }

        let start = range.0;
        let end = start + num;

        MustConsumeIterator {
            inner: start..end,
            debug_info: ty,
        }
    }

    /// Instantiates the ranges with an actual field element `alpha`.
    /// Once you call this function, you cannot register new constraints via [Self::register].
    pub fn instantiate(&mut self, alpha: F) {
        let mut last_power = F::one();
        let mut alphas = Vec::with_capacity(self.next_power as usize);
        alphas.push(F::one());
        for _ in 1..self.next_power {
            last_power *= alpha;
            alphas.push(last_power);
        }
        self.alphas = Some(alphas);
    }

    /// This function allows us to retrieve the powers of alpha, upperbounded by `num`
    pub fn get_alphas(
        &self,
        ty: ArgumentType,
        num: u32,
    ) -> MustConsumeIterator<Cloned<Take<Skip<Iter<F>>>>, F> {
        let ty = if matches!(ty, ArgumentType::Gate(_)) {
            ArgumentType::Gate(GateType::Zero)
        } else {
            ty
        };

        let range = self
            .mapping
            .get(&ty)
            .unwrap_or_else(|| panic!("constraint {:?} was not registered", ty));

        if num > range.1 {
            panic!(
                "you asked for {num} alphas, but only {} are available for {:?}",
                range.1, ty
            );
        }

        match &self.alphas {
            None => panic!("you must call instantiate with an actual field element first"),
            Some(alphas) => {
                let alphas_range = alphas
                    .iter()
                    .skip(range.0 as usize)
                    .take(num as usize)
                    .cloned();
                MustConsumeIterator {
                    inner: alphas_range,
                    debug_info: ty,
                }
            }
        }
    }
}

impl<T> Display for Alphas<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for arg in [
            ArgumentType::Gate(GateType::Zero),
            ArgumentType::Permutation,
            //            ArgumentType::Lookup,
        ] {
            let name = if matches!(arg, ArgumentType::Gate(_)) {
                "gates".to_string()
            } else {
                format!("{:?}", arg)
            };
            let range = self
                .mapping
                .get(&arg)
                .expect("you need to register all arguments before calling display");
            writeln!(
                f,
                "* **{}**. Offset starts at {} and {} powers of $\\alpha$ are used",
                name, range.0, range.1
            )?;
        }

        Ok(())
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
    debug_info: ArgumentType,
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
    use std::{fs, path::Path};

    use super::*;
    use crate::circuits::gate::GateType;
    use mina_curves::pasta::Fp;

    // testing [Builder]

    #[test]
    fn incorrect_alpha_powers() {
        let mut alphas = Alphas::<Fp>::default();
        alphas.register(ArgumentType::Gate(GateType::Poseidon), 3);

        let mut powers = alphas.get_exponents(ArgumentType::Gate(GateType::Poseidon), 3);
        assert_eq!(powers.next(), Some(0));
        assert_eq!(powers.next(), Some(1));
        assert_eq!(powers.next(), Some(2));

        alphas.register(ArgumentType::Permutation, 3);
        let mut powers = alphas.get_exponents(ArgumentType::Permutation, 3);

        assert_eq!(powers.next(), Some(3));
        assert_eq!(powers.next(), Some(4));
        assert_eq!(powers.next(), Some(5));
    }

    #[test]
    #[should_panic]
    fn register_after_instantiating() {
        let mut alphas = Alphas::<Fp>::default();
        alphas.instantiate(Fp::from(1));
        alphas.register(ArgumentType::Gate(GateType::Poseidon), 3);
    }

    #[test]
    #[should_panic]
    fn didnt_use_all_alpha_powers() {
        let mut alphas = Alphas::<Fp>::default();
        alphas.register(ArgumentType::Permutation, 7);
        let mut powers = alphas.get_exponents(ArgumentType::Permutation, 3);
        powers.next();
    }

    #[test]
    #[should_panic]
    fn registered_alpha_powers_for_some_constraint_twice() {
        let mut alphas = Alphas::<Fp>::default();
        alphas.register(ArgumentType::Gate(GateType::Poseidon), 2);
        alphas.register(ArgumentType::Gate(GateType::ChaCha0), 3);
    }

    #[test]
    fn powers_of_alpha() {
        let mut alphas = Alphas::default();
        alphas.register(ArgumentType::Gate(GateType::Poseidon), 4);
        let mut powers = alphas.get_exponents(ArgumentType::Gate(GateType::Poseidon), 4);

        assert_eq!(powers.next(), Some(0));
        assert_eq!(powers.next(), Some(1));
        assert_eq!(powers.next(), Some(2));
        assert_eq!(powers.next(), Some(3));

        let alpha = Fp::from(2);
        alphas.instantiate(alpha);

        let mut alphas = alphas.get_alphas(ArgumentType::Gate(GateType::Poseidon), 4);
        assert_eq!(alphas.next(), Some(1.into()));
        assert_eq!(alphas.next(), Some(2.into()));
        assert_eq!(alphas.next(), Some(4.into()));
        assert_eq!(alphas.next(), Some(8.into()));
    }

    // useful for the spec

    use crate::{
        circuits::{gate::CircuitGate, wires::Wire},
        linearization::expr_linearization,
        prover_index::testing::new_index_for_test,
    };

    #[test]
    fn get_alphas_for_spec() {
        let gates = vec![CircuitGate::<Fp>::zero(Wire::new(0)); 2];
        let index = new_index_for_test(gates, 0);
        let (_linearization, powers_of_alpha) = expr_linearization(
            index.cs.domain.d1,
            index.cs.chacha8.is_some(),
            !index.cs.range_check_selector_polys.is_empty(),
            index
                .cs
                .lookup_constraint_system
                .as_ref()
                .map(|lcs| &lcs.configuration),
        );
        // make sure this is present in the specification
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let spec_path = Path::new(&manifest_dir)
            .join("..")
            .join("book")
            .join("specifications")
            .join("kimchi")
            .join("template.md");

        let spec = fs::read_to_string(spec_path).unwrap();
        if !spec.contains(&powers_of_alpha.to_string()) {
            panic!(
                "the specification of kimchi must contain the following paragraph:\n\n{powers_of_alpha}\n\n"
            );
        }
    }
}
