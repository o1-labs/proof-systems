//! This module obtains the gates of a foreign field addition circuit.

use ark_ff::{PrimeField, SquareRootField};
use num_bigint::BigUint;
use o1_utils::foreign_field::{BigUintForeignFieldHelpers, ForeignFieldHelpers};

use crate::{
    alphas::Alphas,
    circuits::{
        expr::{Cache, E},
        gate::GateHelpers,
        gate::{CircuitGate, GateType},
        lookup::{
            self,
            tables::{GateLookupTable, LookupTable},
        },
        polynomials::{generic::GenericGateSpec, zero::Zero},
        wires::Wire,
    },
};

use super::circuitgates::ForeignFieldMul;

/// Number of gates in this gadget
pub const GATE_COUNT: usize = 1;

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
    /// Create foreign field multiplication gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_foreign_field_mul(
        start_row: usize,
        foreign_field_modulus: &BigUint,
    ) -> (usize, Vec<Self>) {
        let neg_foreign_field_modulus = foreign_field_modulus.negate().to_field_limbs::<F>();
        let foreign_field_modulus = foreign_field_modulus.to_field_limbs::<F>();
        let circuit_gates = vec![
            CircuitGate {
                typ: ForeignFieldMul::<F>::typ(),
                wires: Wire::for_row(start_row),
                coeffs: vec![
                    foreign_field_modulus[2],
                    neg_foreign_field_modulus[0],
                    neg_foreign_field_modulus[1],
                    neg_foreign_field_modulus[2],
                ],
            },
            CircuitGate {
                typ: Zero::<F>::typ(),
                wires: Wire::for_row(start_row + 1),
                coeffs: vec![],
            },
        ];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Create foreign field multiplication gate by extending the existing gates
    pub fn extend_foreign_field_mul(
        gates: &mut Vec<Self>,
        curr_row: &mut usize,
        foreign_field_modulus: &BigUint,
    ) {
        let (next_row, circuit_gates) =
            Self::create_foreign_field_mul(*curr_row, foreign_field_modulus);
        *curr_row = next_row;
        gates.extend_from_slice(&circuit_gates);
    }

    pub fn extend_high_bounds(
        gates: &mut Vec<Self>,
        curr_row: &mut usize,
        foreign_field_modulus: &BigUint,
    ) {
        let r = gates.len();
        let hi_fmod = foreign_field_modulus.to_field_limbs::<F>()[2];
        let hi_limb: F = F::two_to_limb() - hi_fmod - F::one();
        let g = GenericGateSpec::Plus(hi_limb);
        CircuitGate::extend_generic(gates, curr_row, Wire::for_row(r), g.clone(), Some(g));
    }
}

/// Get the foreign field multiplication lookup table
pub fn lookup_table<F: PrimeField>() -> LookupTable<F> {
    lookup::tables::get_table::<F>(GateLookupTable::RangeCheck)
}
