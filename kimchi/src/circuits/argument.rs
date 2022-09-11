//! An argument is simply a number of constraints,
//! which we want to enforce on all points of the domain.
//! Both the permutation and the plookup arguments fit this type.
//! Gates can be seen as filtered arguments,
//! which apply only in some points (rows) of the domain.

use crate::{alphas::Alphas, circuits::expr::prologue::*};
use ark_ff::FftField;
use array_init::array_init;
use serde::{Deserialize, Serialize};

use super::{expr::{constraints::ArithmeticOps, Constants, ConstantsEnv}, gate::GateType, polynomial::COLUMNS};

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

pub struct GateWitness<T> {
    pub curr: [T; COLUMNS],
    pub next: [T; COLUMNS],
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
    fn constraints<T: ArithmeticOps<F>>(witness: &GateWitness<T>, constants: ConstantsEnv<F, T>) -> Vec<T>;

    /// Returns the set of constraints required to prove this argument.
    fn expression() -> Vec<E<F>> {
        // Build expr witness
        let witness = GateWitness {
            curr: array_init(|i| witness_curr(i)),
            next: array_init(|i| witness_next(i)),
        };

        // Generate constraints
        Self::constraints(&witness, ConstantsEnv::default())
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
