use std::collections::BTreeMap;

use ark_ff::PrimeField;

use super::{gate::GateHelpers, polynomials};
use crate::circuits::{expr::E, gate::Gate};

pub type GateList<F> = Vec<Box<dyn Gate<F, E<F>>>>;

/// Helper to specify a bunch of gates
#[macro_export]
macro_rules! gates {
    ($($first:ident $(:: $second:ident)*),*) => { {
        let mut gates = GateList::new();
        $( gates.push($first:: $( $second:: )* create()); )*
        gates
    }};
}

// /// Helper to specify a gate type
// #[macro_export]
// macro_rules! gate_type {
//     ($first:ident $(:: $second:ident)* < $typ:ident $(:: $third:ident)* >) => {
//         $first $(:: $second )* < $typ $( :: $third )* >::gate_type()
//     };
// }

// Registry of available gates
#[derive(Clone, Debug)]
pub struct GateRegistry<F: PrimeField> {
    pub gates: BTreeMap<String, Box<dyn Gate<F, E<F>>>>,
}

impl<F: PrimeField> Default for GateRegistry<F> {
    fn default() -> Self {
        let mut registry = Self::new();

        // Register default set of gates
        registry.register(gates![
            polynomials::zero::Zero,
            polynomials::generic::Generic,
            polynomials::poseidon::Poseidon,
            polynomials::complete_add::CompleteAdd,
            polynomials::varbasemul::VarbaseMul,
            polynomials::endosclmul::EndosclMul,
            polynomials::endomul_scalar::EndomulScalar,
            polynomials::turshi::Claim,
            polynomials::turshi::Instruction,
            polynomials::turshi::Flags,
            polynomials::turshi::Transition,
            polynomials::range_check::circuitgates::RangeCheck0,
            polynomials::range_check::circuitgates::RangeCheck1,
            polynomials::foreign_field_add::circuitgates::ForeignFieldAdd,
            polynomials::foreign_field_mul::circuitgates::ForeignFieldMul,
            polynomials::xor::Xor16,
            polynomials::rot::Rot64
        ]);
        registry
    }
}

impl<F: PrimeField> GateRegistry<F> {
    /// Create a new empty GateRegistry
    pub fn new() -> Self {
        Self {
            gates: BTreeMap::new(),
        }
    }

    /// Register a bunch of gates
    pub fn register(&mut self, gates: GateList<F>) {
        for gate in gates {
            self.register_one(gate)
        }
    }

    /// Register a single gate
    pub fn register_one(&mut self, gate: Box<dyn Gate<F, E<F>>>) {
        match self.gates.get_key_value(&gate.typ()) {
            Some(_) => (),
            None => {
                self.gates.insert(gate.typ(), gate);
            }
        }
    }

    /// Obtain a gate from the registry
    pub fn get(&self, name: String) -> Option<&Box<dyn Gate<F, E<F>>>> {
        self.gates.get(&name)
    }

    /// Iterate over the registered gates
    pub fn iter(
        &mut self,
    ) -> std::collections::btree_map::Iter<'_, String, Box<dyn Gate<F, E<F>>>> {
        self.gates.iter()
    }
}
