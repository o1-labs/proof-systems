//! This module implements Plonk constraint gate primitive.

use crate::{
    circuits::{
        argument::{Argument, ArgumentEnv},
        berkeley_columns::BerkeleyChallenges,
        constraints::ConstraintSystem,
        polynomials::{
            complete_add, endomul_scalar, endosclmul, foreign_field_add, foreign_field_mul,
            poseidon, range_check, rot, turshi, varbasemul, xor,
        },
        wires::*,
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use ark_ff::PrimeField;
use o1_utils::hasher::CryptoDigest;
use poly_commitment::OpenProof;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
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
    Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord,
)]
#[cfg_attr(
    feature = "ocaml_types",
    derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Enum)
)]
#[cfg_attr(feature = "wasm_types", wasm_bindgen::prelude::wasm_bindgen)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum GateType {
    #[default]
    /// Zero gate
    Zero,
    /// Generic arithmetic gate
    Generic,
    /// Poseidon permutation gate
    Poseidon,
    /// Complete EC addition in Affine form
    CompleteAdd,
    /// EC variable base scalar multiplication
    VarBaseMul,
    /// EC variable base scalar multiplication with group endomorphim optimization
    EndoMul,
    /// Gate for computing the scalar corresponding to an endoscaling
    EndoMulScalar,
    // Lookup
    Lookup,
    /// Cairo
    CairoClaim,
    CairoInstruction,
    CairoFlags,
    CairoTransition,
    /// Range check
    RangeCheck0,
    RangeCheck1,
    ForeignFieldAdd,
    ForeignFieldMul,
    // Gates for Keccak
    Xor16,
    Rot64,
}

/// Gate error
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitGateError {
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
    /// Invalid lookup
    #[error("Invalid {0:?} lookup constraint")]
    InvalidLookupConstraint(GateType),
    /// Failed to get witness for row
    #[error("Failed to get {0:?} witness for row {1}")]
    FailedToGetWitnessForRow(GateType, usize),
}

/// Gate result
pub type CircuitGateResult<T> = core::result::Result<T, CircuitGateError>;

#[serde_as]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

impl<F> CircuitGate<F>
where
    F: PrimeField,
{
    pub fn new(typ: GateType, wires: GateWires, coeffs: Vec<F>) -> Self {
        Self { typ, wires, coeffs }
    }
}

impl<F: PrimeField> CircuitGate<F> {
    /// this function creates "empty" circuit gate
    pub fn zero(wires: GateWires) -> Self {
        CircuitGate::new(GateType::Zero, wires, vec![])
    }

    /// This function verifies the consistency of the wire
    /// assignments (witness) against the constraints
    ///
    /// # Errors
    ///
    /// Will give error if verify process returns error.
    pub fn verify<G: KimchiCurve<ScalarField = F>, OpeningProof: OpenProof<G>>(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        index: &ProverIndex<G, OpeningProof>,
        public: &[F],
    ) -> Result<(), String> {
        use GateType::*;
        match self.typ {
            Zero => Ok(()),
            Generic => self.verify_generic(row, witness, public),
            Poseidon => self.verify_poseidon::<G>(row, witness),
            CompleteAdd => self.verify_complete_add(row, witness),
            VarBaseMul => self.verify_vbmul(row, witness),
            EndoMul => self.verify_endomul::<G>(row, witness, &index.cs),
            EndoMulScalar => self.verify_endomul_scalar::<G>(row, witness, &index.cs),
            // TODO: implement the verification for the lookup gate
            // See https://github.com/MinaProtocol/mina/issues/14011
            Lookup => Ok(()),
            CairoClaim | CairoInstruction | CairoFlags | CairoTransition => {
                self.verify_cairo_gate::<G>(row, witness, &index.cs)
            }
            RangeCheck0 | RangeCheck1 => self
                .verify_witness::<G>(row, witness, &index.cs, public)
                .map_err(|e| e.to_string()),
            ForeignFieldAdd => self
                .verify_witness::<G>(row, witness, &index.cs, public)
                .map_err(|e| e.to_string()),
            ForeignFieldMul => self
                .verify_witness::<G>(row, witness, &index.cs, public)
                .map_err(|e| e.to_string()),
            Xor16 => self
                .verify_witness::<G>(row, witness, &index.cs, public)
                .map_err(|e| e.to_string()),
            Rot64 => self
                .verify_witness::<G>(row, witness, &index.cs, public)
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
        let constants = expr::Constants {
            endo_coefficient: cs.endo,
            mds: &G::sponge_params().mds,
            zk_rows: cs.zk_rows,
        };
        //TODO : use generic challenges, since we do not need those here
        let challenges = BerkeleyChallenges {
            alpha: F::one(),
            beta: F::one(),
            gamma: F::one(),
            joint_combiner: F::one(),
        };
        // Create the argument environment for the constraints over field elements
        let env = ArgumentEnv::<F, F>::create(
            argument_witness,
            self.coeffs.clone(),
            constants,
            challenges,
        );

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

        let mut cache = expr::Cache::default();

        // Perform witness verification on each constraint for this gate
        let results = match self.typ {
            GateType::Zero => {
                vec![]
            }
            GateType::Generic => {
                // TODO: implement the verification for the generic gate
                vec![]
            }
            GateType::Poseidon => poseidon::Poseidon::constraint_checks(&env, &mut cache),
            GateType::CompleteAdd => complete_add::CompleteAdd::constraint_checks(&env, &mut cache),
            GateType::VarBaseMul => varbasemul::VarbaseMul::constraint_checks(&env, &mut cache),
            GateType::EndoMul => endosclmul::EndosclMul::constraint_checks(&env, &mut cache),
            GateType::EndoMulScalar => {
                endomul_scalar::EndomulScalar::constraint_checks(&env, &mut cache)
            }
            GateType::Lookup => {
                // TODO: implement the verification for the lookup gate
                // See https://github.com/MinaProtocol/mina/issues/14011
                vec![]
            }
            GateType::CairoClaim => turshi::Claim::constraint_checks(&env, &mut cache),
            GateType::CairoInstruction => turshi::Instruction::constraint_checks(&env, &mut cache),
            GateType::CairoFlags => turshi::Flags::constraint_checks(&env, &mut cache),
            GateType::CairoTransition => turshi::Transition::constraint_checks(&env, &mut cache),
            GateType::RangeCheck0 => {
                range_check::circuitgates::RangeCheck0::constraint_checks(&env, &mut cache)
            }
            GateType::RangeCheck1 => {
                range_check::circuitgates::RangeCheck1::constraint_checks(&env, &mut cache)
            }
            GateType::ForeignFieldAdd => {
                foreign_field_add::circuitgates::ForeignFieldAdd::constraint_checks(
                    &env, &mut cache,
                )
            }
            GateType::ForeignFieldMul => {
                foreign_field_mul::circuitgates::ForeignFieldMul::constraint_checks(
                    &env, &mut cache,
                )
            }
            GateType::Xor16 => xor::Xor16::constraint_checks(&env, &mut cache),
            GateType::Rot64 => rot::Rot64::constraint_checks(&env, &mut cache),
        };

        // Check for failed constraints
        for (i, result) in results.iter().enumerate() {
            if !result.is_zero() {
                // Pinpoint failed constraint
                return Err(CircuitGateError::Constraint(self.typ, i + 1));
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
    /// `cell_pre` --> `cell_new` && `cell_new` --> `wire_tmp`
    ///
    /// Note: This function assumes that the targeted cells are freshly instantiated
    ///       with self-connections.  If the two cells are transitively already part
    ///       of the same permutation then this would split it.
    fn connect_cell_pair(&mut self, cell1: (usize, usize), cell2: (usize, usize));

    /// Connects a generic gate cell with zeros to a given row for 64bit range check
    fn connect_64bit(&mut self, zero_row: usize, start_row: usize);

    /// Connects the wires of the range checks in a single foreign field addition
    /// Inputs:
    /// - `ffadd_row`: the row of the foreign field addition gate
    /// - `left_rc`: the first row of the range check for the left input
    /// - `right_rc`: the first row of the range check for the right input
    /// - `out_rc`: the first row of the range check for the output of the addition
    ///
    /// Note:
    ///   If run with `left_rc = None` and `right_rc = None` then it can be used for the bound check range check
    fn connect_ffadd_range_checks(
        &mut self,
        ffadd_row: usize,
        left_rc: Option<usize>,
        right_rc: Option<usize>,
        out_rc: usize,
    );
}

impl<F: PrimeField> Connect for Vec<CircuitGate<F>> {
    fn connect_cell_pair(&mut self, cell_pre: (usize, usize), cell_new: (usize, usize)) {
        let wire_tmp = self[cell_pre.0].wires[cell_pre.1];
        self[cell_pre.0].wires[cell_pre.1] = self[cell_new.0].wires[cell_new.1];
        self[cell_new.0].wires[cell_new.1] = wire_tmp;
    }

    fn connect_64bit(&mut self, zero_row: usize, start_row: usize) {
        // Connect the 64-bit cells from previous Generic gate with zeros in first 12 bits
        self.connect_cell_pair((start_row, 1), (start_row, 2));
        self.connect_cell_pair((start_row, 2), (zero_row, 0));
        self.connect_cell_pair((zero_row, 0), (start_row, 1));
    }

    fn connect_ffadd_range_checks(
        &mut self,
        ffadd_row: usize,
        left_rc: Option<usize>,
        right_rc: Option<usize>,
        out_rc: usize,
    ) {
        if let Some(left_rc) = left_rc {
            // Copy left_input_lo -> Curr(0)
            self.connect_cell_pair((left_rc, 0), (ffadd_row, 0));
            // Copy left_input_mi -> Curr(1)
            self.connect_cell_pair((left_rc + 1, 0), (ffadd_row, 1));
            // Copy left_input_hi -> Curr(2)
            self.connect_cell_pair((left_rc + 2, 0), (ffadd_row, 2));
        }

        if let Some(right_rc) = right_rc {
            // Copy right_input_lo -> Curr(3)
            self.connect_cell_pair((right_rc, 0), (ffadd_row, 3));
            // Copy right_input_mi -> Curr(4)
            self.connect_cell_pair((right_rc + 1, 0), (ffadd_row, 4));
            // Copy right_input_hi -> Curr(5)
            self.connect_cell_pair((right_rc + 2, 0), (ffadd_row, 5));
        }

        // Copy result_lo -> Next(0)
        self.connect_cell_pair((out_rc, 0), (ffadd_row + 1, 0));
        // Copy result_mi -> Next(1)
        self.connect_cell_pair((out_rc + 1, 0), (ffadd_row + 1, 1));
        // Copy result_hi -> Next(2)
        self.connect_cell_pair((out_rc + 2, 0), (ffadd_row + 1, 2));
    }
}

/// A circuit is specified as a public input size and a list of [`CircuitGate`].
#[derive(Serialize)]
#[serde(bound = "CircuitGate<F>: Serialize")]
pub struct Circuit<'a, F: PrimeField> {
    pub public_input_size: usize,
    pub gates: &'a [CircuitGate<F>],
}

impl<'a, F> Circuit<'a, F>
where
    F: PrimeField,
{
    pub fn new(public_input_size: usize, gates: &'a [CircuitGate<F>]) -> Self {
        Self {
            public_input_size,
            gates,
        }
    }
}

impl<F: PrimeField> CryptoDigest for Circuit<'_, F> {
    const PREFIX: &'static [u8; 15] = b"kimchi-circuit0";
}

impl<'a, F> From<&'a ConstraintSystem<F>> for Circuit<'a, F>
where
    F: PrimeField,
{
    fn from(cs: &'a ConstraintSystem<F>) -> Self {
        Self {
            public_input_size: cs.public,
            gates: &cs.gates,
        }
    }
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
            CircuitGate::new(
                typ,
                wires,
                coeffs,
            )
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
