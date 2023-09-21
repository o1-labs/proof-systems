//! This module implements Plonk constraint gate primitive.

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentEnv},
        constraints::ConstraintSystem,
        expr::prologue::*,
        polynomials::{
            complete_add, endomul_scalar, endosclmul, foreign_field_add, foreign_field_mul,
            poseidon, range_check, turshi, varbasemul,
        },
        wires::*,
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use ark_ff::{bytes::ToBytes, PrimeField, SquareRootField};
use dyn_clone::{DynClone, clone_trait_object};
use num_traits::cast::ToPrimitive;
use o1_utils::hasher::CryptoDigest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::io::{Result as IoResult, Write};
use thiserror::Error;

use super::{
    argument::{ArgumentType, ArgumentWitness},
    domains::{Domain, EvaluationDomains},
    expr::{self, constraints::ExprOps, Cache, ConstantExpr},
    polynomials::{generic, rot, xor},
};

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
    Default,
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
    Conditional,
}

impl GateType {
    // TODO: Remove this function once all gates are updated to configurable gates
    pub fn is_always_configured(&self) -> bool {
        matches!(
            self,
            GateType::Zero
                | GateType::Lookup
                | GateType::Generic
                | GateType::Poseidon
                | GateType::CompleteAdd
                | GateType::VarBaseMul
                | GateType::EndoMul
                | GateType::EndoMulScalar
                | GateType::RangeCheck0
                | GateType::RangeCheck1
                | GateType::ForeignFieldAdd
                | GateType::ForeignFieldMul
                | GateType::Xor16
                | GateType::Rot64
        )
    }
    // Get gate definition associated with gate type
    pub fn to_gate<F: PrimeField, T: ExprOps<F>>(&self) -> Option<Box<dyn Gate<F, T>>> {
        match self {
            GateType::Generic => Some(generic::Generic::<F>::create()),
            GateType::Poseidon => Some(poseidon::Poseidon::<F>::create()),
            GateType::CompleteAdd => {
                Some(complete_add::CompleteAdd::<F>::create())
            }
            GateType::VarBaseMul => Some(varbasemul::VarbaseMul::<F>::create()),
            GateType::EndoMul => Some(endosclmul::EndosclMul::<F>::create()),
            GateType::EndoMulScalar => Some(
                endomul_scalar::EndomulScalar::<F>::create(),
            ),
            GateType::RangeCheck0 => Some(
                range_check::circuitgates::RangeCheck0::<F>::create(),
            ),
            GateType::RangeCheck1 => Some(
                range_check::circuitgates::RangeCheck1::<F>::create(),
            ),
            GateType::ForeignFieldAdd => Some(
                foreign_field_add::circuitgates::ForeignFieldAdd::<F>::create(),
            ),
            GateType::ForeignFieldMul => Some(
                foreign_field_mul::circuitgates::ForeignFieldMul::<F>::create(),
            ),
            GateType::Xor16 => Some(xor::Xor16::<F>::create()),
            GateType::Rot64 => Some(rot::Rot64::<F>::create()),
            // TODO: What about Zero and Lookup?
            _ => None,
        }
    }
}

pub trait Gate<F: PrimeField, T: ExprOps<F>>: std::fmt::Debug + DynClone {
    fn name(&self) -> &str;

    fn constraint_checks(
        &self,
        env: &ArgumentEnv<F, T>,
        cache: &mut Cache,
    ) -> Vec<T>;
}

// Implement dynamic cloning
impl<F: PrimeField, T: ExprOps<F>> Clone for Box<dyn Gate<F, T>> {
    fn clone(&self) -> Self {
        dyn_clone::clone_box(&**self)
    }
}

#[macro_export]
macro_rules! define_gate {
    ($name:ident<$typ:ident : $bound:ident > , $comment:literal) => {
        #[doc = "The `"]
        #[doc = stringify!($name)]
        #[doc = "`"]
        #[doc = " gate"]
        #[doc = $comment]
        #[derive(Default, Debug, Clone)]
        pub struct $name<$typ>(PhantomData<$typ>);
        impl<$typ: $bound> $name<F> {
            pub fn create<S: ExprOps<$typ>>() -> Box<dyn Gate<$typ, S>> {
                Box::new(Self::default())
            }
        }
    };
}

pub trait GateHelpers<F: PrimeField> {
    fn constraints(&self, cache: &mut Cache) -> Vec<E<F>>;
    fn constraint_count(&self) -> u32;
    fn combined_constraints(&self, alphas: &Alphas<F>, cache: &mut Cache) -> E<F>;
    fn degree(&self, eval_domains: EvaluationDomains<F>) -> u64;
    fn domain(&self, eval_domains: EvaluationDomains<F>) -> Domain;
    fn latex(&self) -> Vec<Vec<String>>;
}

impl<F> GateHelpers<F> for dyn Gate<F, expr::Expr<ConstantExpr<F>>>
where
    F: PrimeField,
{
    fn constraints(&self, cache: &mut Cache) -> Vec<E<F>>
    {
        // Generate constraints
        self.constraint_checks(&ArgumentEnv::default(), cache)
    }

    fn constraint_count(&self) -> u32
    {
        self.constraints(&mut super::expr::Cache::default()).len() as u32
    }

    fn combined_constraints(&self, alphas: &Alphas<F>, cache: &mut Cache) -> E<F>
    {
        let constraints = self.constraints(cache);
        let alphas =
            alphas.get_exponents(ArgumentType::Gate(GateType::Zero), constraints.len() as u32);
        let combined_constraints = E::combine_constraints(alphas, constraints);

        // TODO: Refactor gate_type into u32
        /* index(gate_type) * */
        combined_constraints
    }

    fn degree(&self, eval_domains: EvaluationDomains<F>) -> u64
    {
        let mut powers_of_alpha = crate::alphas::Alphas::<F>::default();
        powers_of_alpha.register(
            crate::circuits::argument::ArgumentType::Gate(GateType::Zero),
            self.constraint_count(),
        );
        self.combined_constraints(&powers_of_alpha, &mut super::expr::Cache::default())
            .degree(eval_domains.d1.size)
    }

    fn domain(&self, eval_domains: EvaluationDomains<F>) -> Domain
    {
        let degree = self.degree(eval_domains);
        return if degree <= eval_domains.d1.size {
            Domain::D1
        } else if degree <= eval_domains.d2.size {
            Domain::D2
        } else if degree <= eval_domains.d4.size {
            Domain::D4
        } else if degree <= eval_domains.d8.size {
            Domain::D8
        } else {
            panic!("Unsupported gate domain size");
        };
    }

    fn latex(&self) -> Vec<Vec<String>> {
        self.constraints(&mut expr::Cache::default())
            .iter()
            .map(|c| c.latex_str())
            .collect()
    }
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
pub type CircuitGateResult<T> = std::result::Result<T, CircuitGateError>;

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

impl<F: PrimeField> ToBytes for CircuitGate<F> {
    #[inline]
    fn write<W: Write>(&self, mut w: W) -> IoResult<()> {
        let typ: u8 = ToPrimitive::to_u8(&self.typ).unwrap();
        typ.write(&mut w)?;
        for i in 0..COLUMNS {
            self.wires[i].write(&mut w)?;
        }

        (self.coeffs.len() as u8).write(&mut w)?;
        for x in &self.coeffs {
            x.write(&mut w)?;
        }
        Ok(())
    }
}

impl<F: PrimeField + SquareRootField> CircuitGate<F> {
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
    pub fn verify<G: KimchiCurve<ScalarField = F>>(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        index: &ProverIndex<G>,
        public: &[F],
    ) -> Result<(), String> {
        use GateType::*;
        match self.typ {
            Zero => Ok(()),
            // TODO: Refactor these into generic witness verification and replace this function with
            //       verify_witness()
            Generic => self.verify_generic(row, witness, public),
            Poseidon => self.verify_poseidon::<G>(row, witness),
            CompleteAdd => self.verify_complete_add(row, witness),
            VarBaseMul => self.verify_vbmul(row, witness),
            EndoMul => self.verify_endomul::<G>(row, witness, &index.cs),
            EndoMulScalar => self.verify_endomul_scalar::<G>(row, witness, &index.cs),
            // TODO: implement the verification for the lookup gate
            Lookup => Ok(()),
            CairoClaim | CairoInstruction | CairoFlags | CairoTransition => {
                self.verify_cairo_gate::<G>(row, witness, &index.cs)
            }
            // All other gates support generic witness verification
            _ => {
                // This could be a configured gate, so use verify_witness, which also covers those
                self.verify_witness::<G>(row, witness, &index.cs, public)
                    .map_err(|e| e.to_string())
            }
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

        let mut cache = expr::Cache::default();

        // Perform witness verification on each constraint for this gate
        let results = if let Some(gate) = self.typ.to_gate() {
            gate.constraint_checks(&env, &mut cache)
        } else {
            vec![]
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
    /// Note:
    /// If run with `left_rc = None` and `right_rc = None` then it can be used for the bound check range check
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

impl<'a, F: PrimeField> CryptoDigest for Circuit<'a, F> {
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
