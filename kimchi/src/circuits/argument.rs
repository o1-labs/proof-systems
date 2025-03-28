//! An argument is simply a number of constraints,
//! which we want to enforce on all points of the domain.
//! Both the permutation and the plookup arguments fit this type.
//! Gates can be seen as filtered arguments,
//! which apply only in some points (rows) of the domain.
//! For more info, read book/src/kimchi/arguments.md

use core::marker::PhantomData;

use crate::{alphas::Alphas, circuits::expr::prologue::*};
use ark_ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};

//TODO use generic challenge
use super::{
    berkeley_columns::{BerkeleyChallengeTerm, BerkeleyChallenges},
    expr::{constraints::ExprOps, Cache, ConstantExpr, ConstantTerm, Constants},
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

/// The argument environment is used to specify how the argument's constraints are
/// represented when they are built.  If the environment is created without ArgumentData
/// and with `F = Expr<F>`, then the constraints are built as Expr expressions (e.g. for
/// use with the prover/verifier).  On the other hand, if the environment is
/// created with ArgumentData and F = Field or F = PrimeField, then the constraints
/// are built as expressions of real field elements and can be evaluated directly on
/// the witness without using the prover.
pub struct ArgumentEnv<F: 'static, T> {
    data: Option<ArgumentData<F>>,
    phantom_data: PhantomData<T>,
}

impl<F, T> Default for ArgumentEnv<F, T> {
    /// Initialize the environment for creating Expr constraints for use with prover/verifier
    fn default() -> Self {
        ArgumentEnv {
            data: None,
            phantom_data: PhantomData,
        }
    }
}

impl<F: Field, T: ExprOps<F, BerkeleyChallengeTerm>> ArgumentEnv<F, T> {
    /// Initialize the environment for creating constraints of real field elements that can be
    /// evaluated directly over the witness without the prover/verifier
    pub fn create(
        witness: ArgumentWitness<F>,
        coeffs: Vec<F>,
        constants: Constants<F>,
        challenges: BerkeleyChallenges<F>,
    ) -> Self {
        ArgumentEnv {
            data: Some(ArgumentData {
                witness,
                coeffs,
                constants,
                challenges,
            }),
            phantom_data: PhantomData,
        }
    }

    /// Witness cell (row, col)
    pub fn witness(&self, row: CurrOrNext, col: usize) -> T {
        T::witness(row, col, self.data.as_ref())
    }

    /// Witness cell on current row
    pub fn witness_curr(&self, col: usize) -> T {
        T::witness(Curr, col, self.data.as_ref())
    }

    /// Witness cell on next row
    pub fn witness_next(&self, col: usize) -> T {
        T::witness(Next, col, self.data.as_ref())
    }

    /// Witness cells in current row in an interval [from, to)
    pub fn witness_curr_chunk(&self, from: usize, to: usize) -> Vec<T> {
        let mut chunk = Vec::with_capacity(to - from);
        for i in from..to {
            chunk.push(self.witness_curr(i));
        }
        chunk
    }

    /// Witness cells in next row in an interval [from, to)
    pub fn witness_next_chunk(&self, from: usize, to: usize) -> Vec<T> {
        let mut chunk = Vec::with_capacity(to - from);
        for i in from..to {
            chunk.push(self.witness_next(i));
        }
        chunk
    }

    /// Coefficient value at index idx
    pub fn coeff(&self, idx: usize) -> T {
        T::coeff(idx, self.data.as_ref())
    }

    /// Chunk of consecutive coefficients in an interval [from, to)
    pub fn coeff_chunk(&self, from: usize, to: usize) -> Vec<T> {
        let mut chunk = Vec::with_capacity(to - from);
        for i in from..to {
            chunk.push(self.coeff(i));
        }
        chunk
    }

    /// Constant value (see [ConstantExpr] for supported constants)
    pub fn constant(&self, expr: ConstantExpr<F, BerkeleyChallengeTerm>) -> T {
        T::constant(expr, self.data.as_ref())
    }

    /// Helper to access endomorphism coefficient constant
    pub fn endo_coefficient(&self) -> T {
        T::constant(
            ConstantExpr::from(ConstantTerm::EndoCoefficient),
            self.data.as_ref(),
        )
    }

    /// Helper to access maximum distance separable matrix constant at row, col
    pub fn mds(&self, row: usize, col: usize) -> T {
        T::constant(
            ConstantExpr::from(ConstantTerm::Mds { row, col }),
            self.data.as_ref(),
        )
    }
}

/// Argument environment data for constraints of field elements
pub struct ArgumentData<F: 'static> {
    /// Witness rows
    pub witness: ArgumentWitness<F>,
    /// Gate coefficients
    pub coeffs: Vec<F>,
    /// Constants
    pub constants: Constants<F>,
    pub challenges: BerkeleyChallenges<F>,
}

/// Witness data for an argument
pub struct ArgumentWitness<T> {
    /// Witness for current row
    pub curr: [T; COLUMNS],
    /// Witness for next row
    pub next: [T; COLUMNS],
}

impl<T> core::ops::Index<(CurrOrNext, usize)> for ArgumentWitness<T> {
    type Output = T;

    fn index(&self, idx: (CurrOrNext, usize)) -> &T {
        match idx.0 {
            Curr => &self.curr[idx.1],
            Next => &self.next[idx.1],
        }
    }
}

/// The interface for a minimal argument implementation.
pub trait Argument<F: PrimeField> {
    /// The type of constraints that this will produce.
    /// This is important to enforce that we don't combine the constraints
    /// with powers of alpha that collide with other mutually inclusive arguments.
    const ARGUMENT_TYPE: ArgumentType;

    /// The number of constraints created by the argument.
    const CONSTRAINTS: u32;

    /// Constraints for this argument
    fn constraint_checks<T: ExprOps<F, BerkeleyChallengeTerm>>(
        env: &ArgumentEnv<F, T>,
        cache: &mut Cache,
    ) -> Vec<T>;

    /// Returns the set of constraints required to prove this argument.
    fn constraints(cache: &mut Cache) -> Vec<E<F>> {
        // Generate constraints
        Self::constraint_checks(&ArgumentEnv::default(), cache)
    }

    /// Returns constraints safely combined via the passed combinator.
    fn combined_constraints(alphas: &Alphas<F>, cache: &mut Cache) -> E<F> {
        let constraints = Self::constraints(cache);
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

pub trait DynArgument<F: PrimeField> {
    fn constraints(&self, cache: &mut Cache) -> Vec<E<F>>;
    fn combined_constraints(&self, alphas: &Alphas<F>, cache: &mut Cache) -> E<F>;
    fn argument_type(&self) -> ArgumentType;
}

impl<F: PrimeField, T: Argument<F>> DynArgument<F> for T {
    fn constraints(&self, cache: &mut Cache) -> Vec<E<F>> {
        <Self as Argument<F>>::constraints(cache)
    }
    fn combined_constraints(&self, alphas: &Alphas<F>, cache: &mut Cache) -> E<F> {
        <Self as Argument<F>>::combined_constraints(alphas, cache)
    }
    fn argument_type(&self) -> ArgumentType {
        <Self as Argument<F>>::ARGUMENT_TYPE
    }
}
