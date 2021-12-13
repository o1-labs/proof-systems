//! Non-native field multiplication
//!
//! https://hackmd.io/@arielg/B13JoihA8
//!
//! Inputs:
//!     * p: non-native field modulus
//!     * a: first operand a \in Fp
//!     * b: second operand b \in Fp
//!
//! Witness:
//!     * r: multiplication result r = a*b in Fp
//!     ? q: other witness data
//!
//! Parameters:
//!     * n: native field modulus
//!     * t: such that 2^t*n < p^2
//!
//! Equations:
//!
//!     General idea
//!
//!         Equation: a*b = q*p + r
//!
//!         1. Let M = 2^t*n
//!         2. Check a*b = qp + r (mod 2^t)
//!                  a*b = qp + r (mod n)
//!         3. Check a*b < M
//!                  qp + r < M
//!
//!
//!         (2) using CRT implies a*b = qp + r (mod M)
//!         (3) equation holds over integers
//!         => a*b = r (mod p)
//!            r is correct multiplication result
//!
//!     Check that
//!         a*b = q*p + r
//!     where q and r are witnesses s.t. ab - qp - r = 0
//!
//!     * Compute CRT modulus 2^t
//!     * Compute p' = -p mod 2^t
//!
//! Constraints:

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use ark_ff::FftField;

impl<F: FftField> CircuitGate<F> {
    pub fn create_nnmul(wires: &[GateWires; 2]) -> Vec<Self> {
        vec![
            CircuitGate {
                typ: GateType::Nnmul,
                wires: wires[0],
                c: vec![],
            },
            CircuitGate {
                typ: GateType::Zero,
                wires: wires[1],
                c: vec![],
            },
        ]
    }

    pub fn verify_nnmul(&self, _row: usize, _witness: &[Vec<F>; COLUMNS]) -> Result<(), String> {
        // Check a*b
        Ok(())
    }

    pub fn nnmul(&self) -> F {
        if self.typ == GateType::Nnmul {
            F::one()
        } else {
            F::zero()
        }
    }
}
