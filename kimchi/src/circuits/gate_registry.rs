use std::collections::BTreeMap;

use ark_ff::PrimeField;

use crate::circuits::{expr::E, gate::Gate, polynomials};

pub type GateDef<F> = (Box<dyn Gate<F, E<F>>>, Box<dyn Gate<F, F>>);
pub type GateList<F> = Vec<GateDef<F>>;

/// Helper to specify a bunch of gates
#[macro_export]
macro_rules! gates {
    ($($first:ident $(:: $second:ident)*),*) => { {
        // let mut gates = vec![];
        // $( gates.push(($first:: $( $second:: )* create(), $first:: $( $second:: )* create())); )*
        // gates
        // JES: TODO: remove comment
        vec![
        $( ($first:: $( $second:: )* create(), $first:: $( $second:: )* create()), )*
        ]
    }};
}

// Registry of available gates
#[derive(Clone, Debug)]
pub struct GateRegistry<F: PrimeField> {
    expressions: BTreeMap<String, Box<dyn Gate<F, E<F>>>>,
    verifiers: BTreeMap<String, Box<dyn Gate<F, F>>>,
}

impl<F: PrimeField> Default for GateRegistry<F> {
    fn default() -> Self {
        let mut registry = Self::new();

        // Register default set of gates
        registry.register(gates![
            polynomials::zero::Zero,
            polynomials::lookup::Lookup,
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
            expressions: BTreeMap::new(),
            verifiers: BTreeMap::new(),
        }
    }

    /// Get the number of registered gates
    pub fn count(&self) -> usize {
        self.expressions.len()
    }

    /// Register a bunch of gates
    pub fn register(&mut self, gates: GateList<F>) {
        for gate in gates {
            self.register_one(gate)
        }
    }

    /// Register a single gate
    pub fn register_one(&mut self, gate: GateDef<F>) {
        match self.expressions.get_key_value(&gate.0.typ()) {
            Some(_) => (),
            None => {
                self.expressions.insert(gate.0.typ(), gate.0);
                self.verifiers.insert(gate.1.typ(), gate.1);
            }
        }
    }

    /// Obtain a gate from the registry
    pub fn get(&self, name: String) -> Option<&Box<dyn Gate<F, F>>> {
        self.verifiers.get(&name)
    }

    /// Iterate over the registered gates
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, Box<dyn Gate<F, E<F>>>> {
        self.expressions.iter()
    }
}
