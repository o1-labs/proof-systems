//! This module implements Plonk constraint gate primitive.

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv},
        constraints::ConstraintSystem,
        polynomials::{
            chacha, complete_add, endomul_scalar, endosclmul, poseidon, range_check, turshi,
            varbasemul,
        },
        wires::*,
    },
    curve::KimchiCurve,
};
use ark_ff::{bytes::ToBytes, PrimeField};
use ark_poly::Evaluations;
use ark_poly::Radix2EvaluationDomain as D;
use num_traits::cast::ToPrimitive;
use o1_utils::hasher::CryptoDigest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::io::{Result as IoResult, Write};
use thiserror::Error;

use super::{argument::ArgumentWitness, expr};

/// A row accessible from a given row, corresponds to the fact that we open all polynomials
/// at `zeta` **and** `omega * zeta`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum CurrOrNext {
    Curr,
    Next,
}

impl CurrOrNext {
    /// Compute the offset corresponding to the `CurrOrNext` value.
    /// - `Curr.shift() == 0`
    /// - `Next.shift() == 1`
    pub fn shift(&self) -> usize {
        match self {
            CurrOrNext::Curr => 0,
            CurrOrNext::Next => 1,
        }
    }
}

/// The different types of gates the system supports.
/// Note that all the gates are mutually exclusive:
/// they cannot be used at the same time on single row.
/// If we were ever to support this feature, we would have to make sure
/// not to re-use powers of alpha across constraints.
#[repr(C)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum GateType {
    /// Zero gate
    Zero = 0,
    /// Generic arithmetic gate
    Generic = 1,
    /// Poseidon permutation gate
    Poseidon = 2,
    /// Complete EC addition in Affine form
    CompleteAdd = 3,
    /// EC variable base scalar multiplication
    VarBaseMul = 4,
    /// EC variable base scalar multiplication with group endomorphim optimization
    EndoMul = 5,
    /// Gate for computing the scalar corresponding to an endoscaling
    EndoMulScalar = 6,
    /// ChaCha
    ChaCha0 = 7,
    ChaCha1 = 8,
    ChaCha2 = 9,
    ChaChaFinal = 10,
    // Lookup
    Lookup = 11,
    /// Cairo
    CairoClaim = 12,
    CairoInstruction = 13,
    CairoFlags = 14,
    CairoTransition = 15,
    /// Range check (16-24)
    RangeCheck0 = 16,
    RangeCheck1 = 17,
    // ForeignFieldAdd = 25,
    // ForeignFieldMul = 26,
}

/// Selector polynomial
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SelectorPolynomial<F: PrimeField> {
    /// Evaluation form (evaluated over domain d8)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub eval8: Evaluations<F, D<F>>,
}

/// Gate error
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitGateError {
    /// Invalid constraint
    #[error("Invalid circuit gate type {0:?}")]
    InvalidCircuitGateType(GateType),
    /// Invalid constraint
    #[error("Invalid {0:?} constraint")]
    InvalidConstraint(GateType),
    /// Invalid constraint with number
    #[error("Invalid {0:?} constraint: {1}")]
    Constraint(GateType, usize),
    /// Invalid wire column
    #[error("Invalid {0:?} wire column: {1}")]
    WireColumn(GateType, usize),
    /// Disconnected wires
    #[error("Invalid {typ:?} copy constraint: {},{} -> {},{}", .src.row, .src.col, .dst.row, .dst.col)]
    CopyConstraint { typ: GateType, src: Wire, dst: Wire },
    /// Invalid copy constraint
    #[error("Invalid {0:?} copy constraint")]
    InvalidCopyConstraint(GateType),
    /// Invalid lookup constraint - sorted evaluations
    #[error("Invalid {0:?} lookup constraint - sorted evaluations")]
    InvalidLookupConstraintSorted(GateType),
    /// Invalid lookup constraint - sorted evaluations
    #[error("Invalid {0:?} lookup constraint - aggregation polynomial")]
    InvalidLookupConstraintAggregation(GateType),
    /// Missing lookup constraint system
    #[error("Failed to get lookup constraint system for {0:?}")]
    MissingLookupConstraintSystem(GateType),
    /// Failed to get witness for row
    #[error("Failed to get {0:?} witness for row {1}")]
    FailedToGetWitnessForRow(GateType, usize),
}

/// Gate result
pub type CircuitGateResult<T> = std::result::Result<T, CircuitGateError>;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
/// A single gate in a circuit.
pub struct CircuitGate<F: PrimeField> {
    /// type of the gate
    pub typ: GateType,
    /// gate wiring (for each cell, what cell it is wired to)
    pub wires: GateWires,
    /// public selector polynomials that can used as handy coefficients in gates
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub coeffs: Vec<F>,
}

impl<F: PrimeField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        let typ: u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {
            self.wires[i].write(&mut w)?
        }

        (self.coeffs.len() as u8).write(&mut w)?;
        for x in &self.coeffs {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: PrimeField> CircuitGate<F> {
    /// this function creates "empty" circuit gate
    pub fn zero(wires: GateWires) -> Self {
        CircuitGate {
            typ: GateType::Zero,
            wires,
            coeffs: Vec::new(),
        }
    }

    /// This function verifies the consistency of the wire
    /// assignments (witness) against the constraints
    pub fn verify<G: KimchiCurve<ScalarField = F>>(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
        public: &[F],
    ) -> Result<(), String> {
        use GateType::*;
        match self.typ {
            Zero => Ok(()),
            Generic => self.verify_generic(row, witness, public),
            Poseidon => self.verify_poseidon::<G>(row, witness),
            CompleteAdd => self.verify_complete_add(row, witness),
            VarBaseMul => self.verify_vbmul(row, witness),
            EndoMul => self.verify_endomul::<G>(row, witness, cs),
            EndoMulScalar => self.verify_endomul_scalar::<G>(row, witness, cs),
            // TODO: implement the verification for chacha
            ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal => Ok(()),
            // TODO: implement the verification for the lookup gate
            Lookup => Ok(()),
            CairoClaim | CairoInstruction | CairoFlags | CairoTransition => {
                self.verify_cairo_gate::<G>(row, witness, cs)
            }
            RangeCheck0 | RangeCheck1 => self
                .verify_range_check::<G>(row, witness, cs)
                .map_err(|e| e.to_string()),
        }
    }

    /// Verify the witness against the constraints
    pub fn verify_witness<G: KimchiCurve<ScalarField = F>>(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
        _public: &[F],
    ) -> CircuitGateResult<()> {
        // Grab the relevant part of the witness
        let argument_witness = self.argument_witness(row, witness)?;
        // Set up the constants.  Note that alpha, beta, gamma and joint_combiner
        // are one because this function is not running the prover.
        let constants = expr::Constants::<F> {
            alpha: F::one(),
            beta: F::one(),
            gamma: F::one(),
            joint_combiner: Some(F::one()),
            endo_coefficient: cs.endo,
            mds: &G::sponge_params().mds,
        };
        // Create the argument environment for the constraints over field elements
        let env = ArgumentEnv::<F, F>::create(argument_witness, self.coeffs.clone(), constants);

        // Check the wiring (i.e. copy constraints) for this gate
        // Note: Gates can operated on row Curr or Curr and Next.
        //       It could be nice for gates to know this and then
        //       this code could be adapted to check Curr or Curr
        //       and Next depending on the gate definition
        for col in 0..PERMUTS {
            let wire = self.wires[col];

            if wire.col >= PERMUTS {
                return Err(CircuitGateError::WireColumn(self.typ, col));
            }

            if witness[col][row] != witness[wire.col][wire.row] {
                // Pinpoint failed copy constraint
                return Err(CircuitGateError::CopyConstraint {
                    typ: self.typ,
                    src: Wire { row, col },
                    dst: wire,
                });
            }
        }

        // Perform witness verification on each constraint for this gate
        let results = match self.typ {
            GateType::Zero => {
                vec![]
            }
            GateType::Generic => {
                // TODO: implement the verification for the generic gate
                vec![]
            }
            GateType::Poseidon => poseidon::Poseidon::constraint_checks(&env),
            GateType::CompleteAdd => complete_add::CompleteAdd::constraint_checks(&env),
            GateType::VarBaseMul => varbasemul::VarbaseMul::constraint_checks(&env),
            GateType::EndoMul => endosclmul::EndosclMul::constraint_checks(&env),
            GateType::EndoMulScalar => endomul_scalar::EndomulScalar::constraint_checks(&env),
            GateType::ChaCha0 => chacha::ChaCha0::constraint_checks(&env),
            GateType::ChaCha1 => chacha::ChaCha1::constraint_checks(&env),
            GateType::ChaCha2 => chacha::ChaCha2::constraint_checks(&env),
            GateType::ChaChaFinal => chacha::ChaChaFinal::constraint_checks(&env),
            GateType::Lookup => {
                // TODO: implement the verification for the lookup gate
                vec![]
            }
            GateType::CairoClaim => turshi::Claim::constraint_checks(&env),
            GateType::CairoInstruction => turshi::Instruction::constraint_checks(&env),
            GateType::CairoFlags => turshi::Flags::constraint_checks(&env),
            GateType::CairoTransition => turshi::Transition::constraint_checks(&env),
            GateType::RangeCheck0 => {
                range_check::circuitgates::RangeCheck0::constraint_checks(&env)
            }
            GateType::RangeCheck1 => {
                range_check::circuitgates::RangeCheck1::constraint_checks(&env)
            }
        };

        // Check for failed constraints
        for (i, result) in results.iter().enumerate() {
            if !result.is_zero() {
                // Pinpoint failed constraint
                return Err(CircuitGateError::Constraint(self.typ, i));
            }
        }

        // TODO: implement generic plookup witness verification

        Ok(())
    }

    // Return the part of the witness relevant to this gate at the given row offset
    fn argument_witness(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
    ) -> CircuitGateResult<ArgumentWitness<F>> {
        // Get the part of the witness relevant to this gate
        let witness_curr: [F; COLUMNS] = (0..witness.len())
            .map(|col| witness[col][row])
            .collect::<Vec<F>>()
            .try_into()
            .map_err(|_| CircuitGateError::FailedToGetWitnessForRow(self.typ, row))?;
        let witness_next: [F; COLUMNS] = if witness[0].len() > row + 1 {
            (0..witness.len())
                .map(|col| witness[col][row + 1])
                .collect::<Vec<F>>()
                .try_into()
                .map_err(|_| CircuitGateError::FailedToGetWitnessForRow(self.typ, row))?
        } else {
            [F::zero(); COLUMNS]
        };

        Ok(ArgumentWitness::<F> {
            curr: witness_curr,
            next: witness_next,
        })
    }
}

/// Trait to connect a pair of cells in a circuit
pub trait Connect {
    /// Connect the pair of cells specified by the cell1 and cell2 parameters
    /// cell_pre --> cell_new && cell_new --> wire_tmp
    ///
    /// Note: This function assumes that the targeted cells are freshly instantiated
    ///       with self-connections.  If the two cells are transitively already part
    ///       of the same permutation then this would split it.
    fn connect_cell_pair(&mut self, cell1: (usize, usize), cell2: (usize, usize));
}

impl<F: PrimeField> Connect for Vec<CircuitGate<F>> {
    fn connect_cell_pair(&mut self, cell_pre: (usize, usize), cell_new: (usize, usize)) {
        let wire_tmp = self[cell_pre.0].wires[cell_pre.1];
        self[cell_pre.0].wires[cell_pre.1] = self[cell_new.0].wires[cell_new.1];
        self[cell_new.0].wires[cell_new.1] = wire_tmp;
    }
}

/// A circuit is specified as a series of [CircuitGate].
#[derive(Serialize)]
pub struct Circuit<'a, F: PrimeField>(
    #[serde(bound = "CircuitGate<F>: Serialize")] pub &'a [CircuitGate<F>],
);

impl<'a, F: PrimeField> CryptoDigest for Circuit<'a, F> {
    const PREFIX: &'static [u8; 15] = b"kimchi-circuit0";
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::circuits::wires::caml::CamlWire;
    use itertools::Itertools;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlCircuitGate<F> {
        pub typ: GateType,
        pub wires: (
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
            CamlWire,
        ),
        pub coeffs: Vec<F>,
    }

    impl<F, CamlF> From<CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: PrimeField,
    {
        fn from(cg: CircuitGate<F>) -> Self {
            Self {
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                coeffs: cg.coeffs.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<&CircuitGate<F>> for CamlCircuitGate<CamlF>
    where
        CamlF: From<F>,
        F: PrimeField,
    {
        fn from(cg: &CircuitGate<F>) -> Self {
            Self {
                typ: cg.typ,
                wires: array_to_tuple(cg.wires),
                coeffs: cg.coeffs.clone().into_iter().map(Into::into).collect(),
            }
        }
    }

    impl<F, CamlF> From<CamlCircuitGate<CamlF>> for CircuitGate<F>
    where
        F: From<CamlF>,
        F: PrimeField,
    {
        fn from(ccg: CamlCircuitGate<CamlF>) -> Self {
            Self {
                typ: ccg.typ,
                wires: tuple_to_array(ccg.wires),
                coeffs: ccg.coeffs.into_iter().map(Into::into).collect(),
            }
        }
    }

    /// helper to convert array to tuple (OCaml doesn't have fixed-size arrays)
    fn array_to_tuple<T1, T2>(a: [T1; PERMUTS]) -> (T2, T2, T2, T2, T2, T2, T2)
    where
        T1: Clone,
        T2: From<T1>,
    {
        a.into_iter()
            .map(Into::into)
            .next_tuple()
            .expect("bug in array_to_tuple")
    }

    /// helper to convert tuple to array (OCaml doesn't have fixed-size arrays)
    fn tuple_to_array<T1, T2>(a: (T1, T1, T1, T1, T1, T1, T1)) -> [T2; PERMUTS]
    where
        T2: From<T1>,
    {
        [
            a.0.into(),
            a.1.into(),
            a.2.into(),
            a.3.into(),
            a.4.into(),
            a.5.into(),
            a.6.into(),
        ]
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand as _;
    use mina_curves::pasta::Fp;
    use proptest::prelude::*;
    use rand::SeedableRng as _;

    // TODO: move to mina-curves
    prop_compose! {
        pub fn arb_fp()(seed: [u8; 32]) -> Fp {
            let rng = &mut rand::rngs::StdRng::from_seed(seed);
            Fp::rand(rng)
        }
    }

    prop_compose! {
        fn arb_fp_vec(max: usize)(seed: [u8; 32], num in 0..max) -> Vec<Fp> {
            let rng = &mut rand::rngs::StdRng::from_seed(seed);
            let mut v = vec![];
            for _ in 0..num {
                v.push(Fp::rand(rng))
            }
            v
        }
    }

    prop_compose! {
        fn arb_circuit_gate()(typ: GateType, wires: GateWires, coeffs in arb_fp_vec(25)) -> CircuitGate<Fp> {
            CircuitGate {
                typ,
                wires,
                coeffs,
            }
        }
    }

    proptest! {
        #[test]
        fn test_gate_serialization(cg in arb_circuit_gate()) {
            let encoded = rmp_serde::to_vec(&cg).unwrap();
            let decoded: CircuitGate<Fp> = rmp_serde::from_slice(&encoded).unwrap();
            prop_assert_eq!(cg.typ, decoded.typ);
            for i in 0..PERMUTS {
                prop_assert_eq!(cg.wires[i], decoded.wires[i]);
            }
            prop_assert_eq!(cg.coeffs, decoded.coeffs);
        }
    }
}
