//! An argument is simply a number of constraints,
//! which we want to enforce on all points of the domain.
//! Both the permutation and the plookup arguments fit this type.
//! Gates can be seen as filtered arguments,
//! which apply only in some points (rows) of the domain.

use std::marker::PhantomData;

use crate::{alphas::Alphas, circuits::expr::prologue::*};
use ark_ff::{FftField, Field};
use serde::{Deserialize, Serialize};

use super::{
    expr::{constraints::ArithmeticOps, ConstantExpr, Constants},
    gate::{CurrOrNext, GateType},
    polynomial::COLUMNS,
};
use CurrOrNext::{Curr, Next};

/// A constraint type represents a polynomial that will be part of the final equation f (the circuit equation)
#[derive(PartialEq, Eq, Clone, Copy, Hash, Debug, Serialize, Deserialize)]
pub enum ArgumentType {
    /// Gates in the PLONK constraint system.
    /// As gates are mutually exclusive (a single gate is set per row),
    /// we can reuse the same powers of alpha across gates.
    Gate(GateType),
    /// The permutation argument
    Permutation,
    /// The lookup argument
    Lookup,
}

pub struct ArgumentData<F: 'static> {
    pub witness: GateWitness<F>,
    pub coeffs: Vec<F>,
    pub constants: Constants<F>,
}
pub struct ArgumentEnv<F: 'static, T> {
    data: Option<ArgumentData<F>>,
    phantom_data: PhantomData<T>,
}

impl<F, T> Default for ArgumentEnv<F, T> {
    fn default() -> Self {
        ArgumentEnv {
            data: None,
            phantom_data: PhantomData,
        }
    }
}

impl<F: Field, T: ArithmeticOps<F>> ArgumentEnv<F, T> {
    pub fn create(witness: GateWitness<F>, coeffs: Vec<F>, constants: Constants<F>) -> Self {
        ArgumentEnv {
            data: Some(ArgumentData {
                witness,
                coeffs,
                constants,
            }),
            phantom_data: PhantomData,
        }
    }

    pub fn witness(&self, row: CurrOrNext, col: usize) -> T {
        T::witness(row, col, self.data.as_ref())
    }

    pub fn witness_curr(&self, col: usize) -> T {
        T::witness(Curr, col, self.data.as_ref())
    }

    pub fn witness_next(&self, col: usize) -> T {
        T::witness(Next, col, self.data.as_ref())
    }

    pub fn coeff(&self, idx: usize) -> T {
        T::coeff(idx, self.data.as_ref())
    }

    pub fn constant(&self, expr: ConstantExpr<F>) -> T {
        T::constant(expr, self.data.as_ref())
    }

    pub fn endo_coefficient(&self) -> T {
        T::constant(ConstantExpr::<F>::EndoCoefficient, self.data.as_ref())
    }

    pub fn mds(&self, row: usize, col: usize) -> T {
        T::constant(ConstantExpr::<F>::Mds { row, col }, self.data.as_ref())
    }
}

pub struct GateWitness<T> {
    pub curr: [T; COLUMNS],
    pub next: [T; COLUMNS],
}

impl<T> std::ops::Index<(CurrOrNext, usize)> for GateWitness<T> {
    type Output = T;

    fn index(&self, idx: (CurrOrNext, usize)) -> &T {
        match idx.0 {
            Curr => &self.curr[idx.1],
            Next => &self.next[idx.1],
        }
    }
}

/// The interface for a minimal argument implementation.
pub trait Argument<F: FftField> {
    /// The type of constraints that this will produce.
    /// This is important to enforce that we don't combine the constraints
    /// with powers of alpha that collide with other mutually inclusive arguments.
    const ARGUMENT_TYPE: ArgumentType;

    /// The number of constraints created by the argument.
    const CONSTRAINTS: u32;

    /// Constraints for this argument
    fn constraints<T: ArithmeticOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T>;

    /// Returns the set of constraints required to prove this argument.
    fn expression() -> Vec<E<F>> {
        // Generate constraints
        Self::constraints(&ArgumentEnv::default())
    }

    /// Returns constraints safely combined via the passed combinator.
    fn combined_constraints(alphas: &Alphas<F>) -> E<F> {
        let constraints = Self::expression();
        assert_eq!(constraints.len(), Self::CONSTRAINTS as usize);
        let alphas = alphas.get_exponents(Self::ARGUMENT_TYPE, Self::CONSTRAINTS);
        let combined_constraints = E::combine_constraints(alphas, constraints);

        // An optional gate type, if used to define a gate.
        // This is used to filter the gate, to avoid applying it on the entire domain.
        if let ArgumentType::Gate(gate_type) = Self::ARGUMENT_TYPE {
            index(gate_type) * combined_constraints
        } else {
            combined_constraints
        }
    }
}
