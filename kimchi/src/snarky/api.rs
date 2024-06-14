//! The main interface to using Snarky.
//!
//! To use Snarky, simply implements the [SnarkyCircuit] trait.

use std::marker::PhantomData;

use crate::{
    circuits::{constraints::ConstraintSystem, gate::CircuitGate, polynomial::COLUMNS},
    curve::KimchiCurve,
    groupmap::GroupMap,
    mina_poseidon::FqSponge,
    plonk_sponge::FrSponge,
    proof::ProverProof,
    prover_index::ProverIndex,
    verifier::verify,
    verifier_index::VerifierIndex,
};

use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use log::debug;
use poly_commitment::{commitment::CommitmentCurve, OpenProof, SRS};

use super::{errors::SnarkyResult, runner::RunState, snarky_type::SnarkyType};

/// A witness represents the execution trace of a circuit.
#[derive(Debug)]
pub struct Witness<F>(pub [Vec<F>; COLUMNS]);

//
// aliases
//

type ScalarField<C> = <C as AffineCurve>::ScalarField;
type BaseField<C> = <C as AffineCurve>::BaseField;

/// A prover index.
pub struct ProverIndexWrapper<Circuit>
where
    Circuit: SnarkyCircuit,
{
    compiled_circuit: CompiledCircuit<Circuit>,
    index: ProverIndex<Circuit::Curve, Circuit::Proof>,
}

type Proof<C> = ProverProof<<C as SnarkyCircuit>::Curve, <C as SnarkyCircuit>::Proof>;
type Output<C> = <<C as SnarkyCircuit>::PublicOutput as SnarkyType<
    ScalarField<<C as SnarkyCircuit>::Curve>,
>>::OutOfCircuit;

impl<Circuit> ProverIndexWrapper<Circuit>
where
    Circuit: SnarkyCircuit,
{
    /// Produces an assembly-like encoding of the circuit.
    pub fn asm(&self) -> String {
        crate::circuits::gate::Circuit::new(
            self.compiled_circuit.public_input_size,
            &self.compiled_circuit.gates,
        )
        .generate_asm()
    }

    /// Produces a proof for the given public input.
    pub fn prove<EFqSponge, EFrSponge>(
        // TODO: this should not be mutable ideally
        &mut self,
        public_input: <Circuit::PublicInput as SnarkyType<ScalarField<Circuit::Curve>>>::OutOfCircuit,
        private_input: Circuit::PrivateInput,
        // TODO: rename to verify_witness?
        debug: bool,
    ) -> SnarkyResult<(Proof<Circuit>, Box<Output<Circuit>>)>
    where
        <Circuit::Curve as AffineCurve>::BaseField: PrimeField,
        EFqSponge: Clone
            + FqSponge<BaseField<Circuit::Curve>, Circuit::Curve, ScalarField<Circuit::Curve>>,
        EFrSponge: FrSponge<ScalarField<Circuit::Curve>>,
    {
        // create public input
        let public_input_without_output =
            Circuit::PublicInput::value_to_field_elements(&public_input).0;

        // init
        self.compiled_circuit
            .sys
            .generate_witness_init(public_input_without_output.clone())?;

        // run circuit and get return var
        let public_input_var: Circuit::PublicInput = self.compiled_circuit.sys.public_input();
        let return_var = self.compiled_circuit.circuit.circuit(
            &mut self.compiled_circuit.sys,
            public_input_var,
            Some(&private_input),
        )?;

        // get values from private input vec
        let (return_cvars, aux) = return_var.to_cvars();
        let mut public_output_values = vec![];
        for cvar in &return_cvars {
            public_output_values.push(cvar.eval(&self.compiled_circuit.sys));
        }

        // create constraint between public output var and return var
        {
            // Note: since the values of the public output part are set to zero at this point,
            // let's also avoid checking the wiring (which would fail)
            let eval_constraints = self.compiled_circuit.sys.eval_constraints;
            self.compiled_circuit.sys.eval_constraints = false;

            self.compiled_circuit.sys.wire_public_output(return_var)?;

            self.compiled_circuit.sys.eval_constraints = eval_constraints;
        }

        // finalize
        let mut witness = self.compiled_circuit.sys.generate_witness();

        // replace public output part of witness
        let start = Circuit::PublicInput::SIZE_IN_FIELD_ELEMENTS;
        let end = start + Circuit::PublicOutput::SIZE_IN_FIELD_ELEMENTS;
        for (cell, val) in &mut witness.0[0][start..end]
            .iter_mut()
            .zip(&public_output_values)
        {
            *cell = *val;
        }

        // same but with the full public input
        let mut public_input_and_output = public_input_without_output;
        public_input_and_output.extend(public_output_values.clone());

        // reconstruct public output
        let public_output =
            Circuit::PublicOutput::value_of_field_elements(public_output_values, aux);

        // verify the witness
        // TODO: return error instead of panicking
        if debug {
            witness.debug();
            self.index
                .verify(&witness.0, &public_input_and_output)
                .unwrap();
        }

        // produce a proof
        let group_map = <Circuit::Curve as CommitmentCurve>::Map::setup();

        // TODO: return error instead of panicking
        let proof: ProverProof<Circuit::Curve, Circuit::Proof> =
            ProverProof::create::<EFqSponge, EFrSponge>(&group_map, witness.0, &[], &self.index)
                .unwrap();

        // return proof + public output
        Ok((proof, Box::new(public_output)))
    }
}

/// A verifier index.
pub struct VerifierIndexWrapper<Circuit>
where
    Circuit: SnarkyCircuit,
{
    index: VerifierIndex<Circuit::Curve, Circuit::Proof>,
}

impl<Circuit> VerifierIndexWrapper<Circuit>
where
    Circuit: SnarkyCircuit,
{
    /// Verify a proof for a given public input and public output.
    pub fn verify<EFqSponge, EFrSponge>(
        &self,
        proof: ProverProof<Circuit::Curve, Circuit::Proof>,
        public_input: <Circuit::PublicInput as SnarkyType<ScalarField<Circuit::Curve>>>::OutOfCircuit,
        public_output: <Circuit::PublicOutput as SnarkyType<ScalarField<Circuit::Curve>>>::OutOfCircuit,
    ) where
        <Circuit::Curve as AffineCurve>::BaseField: PrimeField,
        EFqSponge: Clone
            + FqSponge<BaseField<Circuit::Curve>, Circuit::Curve, ScalarField<Circuit::Curve>>,
        EFrSponge: FrSponge<ScalarField<Circuit::Curve>>,
    {
        let mut public_input = Circuit::PublicInput::value_to_field_elements(&public_input).0;
        public_input.extend(Circuit::PublicOutput::value_to_field_elements(&public_output).0);

        // verify the proof
        let group_map = <Circuit::Curve as CommitmentCurve>::Map::setup();

        verify::<Circuit::Curve, EFqSponge, EFrSponge, Circuit::Proof>(
            &group_map,
            &self.index,
            &proof,
            &public_input,
        )
        .unwrap()
    }
}

//
// Compilation
//

/// A compiled circuit.
// TODO: implement digest function
pub struct CompiledCircuit<Circuit>
where
    Circuit: SnarkyCircuit,
{
    /// The snarky circuit itself.
    circuit: Circuit,

    //// The state after compilation
    sys: RunState<ScalarField<Circuit::Curve>>,

    /// The public input size.
    // TODO: can't we get this from `circuit.public_input_size()`? (easy to implement). Or better, this could be a `Circuit` type that contains the gates as well (or the kimchi ConstraintSystem type)
    public_input_size: usize,

    /// The gates obtained after compilation.
    pub gates: Vec<CircuitGate<ScalarField<Circuit::Curve>>>,
    phantom: PhantomData<Circuit>,
}

/// Compiles a circuit to a [CompiledCircuit].
fn compile<Circuit: SnarkyCircuit>(circuit: Circuit) -> SnarkyResult<CompiledCircuit<Circuit>> {
    // calculate public input size
    let public_input_size = Circuit::PublicInput::SIZE_IN_FIELD_ELEMENTS
        + Circuit::PublicOutput::SIZE_IN_FIELD_ELEMENTS;

    // create snarky constraint system
    let mut sys = RunState::new::<Circuit::Curve>(
        Circuit::PublicInput::SIZE_IN_FIELD_ELEMENTS,
        Circuit::PublicOutput::SIZE_IN_FIELD_ELEMENTS,
        true,
    );

    // run circuit and get return var
    let public_input: Circuit::PublicInput = sys.public_input();
    let return_var = circuit.circuit(&mut sys, public_input, None)?;

    // create constraint between public output var and return var
    // compile to gates
    // TODO: don't panic here, return an error

    let gates = sys.wire_output_and_compile(return_var).unwrap();
    let gates = gates.to_vec();

    // return compiled circuit
    let compiled_circuit = CompiledCircuit {
        circuit,
        sys,
        public_input_size,
        gates,
        phantom: PhantomData,
    };
    Ok(compiled_circuit)
}

//
// The main user-facing trait for constructing circuits.
//

/// The main trait. Implement this on your circuit to get access to more functions (specifically [Self::compile_to_indexes]).
pub trait SnarkyCircuit: Sized {
    /// A circuit must be defined for a specific field,
    /// as it might be incorrect to use a different field.
    /// Currently we specify the field by the curve,
    /// which is more strict and needed due to implementation details in kimchi.
    // TODO: if we remove `sponge_params` from KimchiCurve and move it to the Field then we could specify a field here instead.
    type Curve: KimchiCurve;
    type Proof: OpenProof<Self::Curve>;

    /// The private input used by the circuit.
    type PrivateInput;

    /// The public input used by the circuit.
    type PublicInput: SnarkyType<ScalarField<Self::Curve>>;

    /// The public output returned by the circuit.
    type PublicOutput: SnarkyType<ScalarField<Self::Curve>>;

    /// The circuit. It takes:
    ///
    /// - `self`: to parameterize it at compile time.
    /// - `sys`: to construct the circuit or generate the witness (dpeending on mode)
    /// - `public_input`: the public input (as defined above)
    /// - `private_input`: the private input as an option, set to `None` for compilation.
    ///
    /// It returns a [SnarkyResult] containing the public output.
    fn circuit(
        &self,
        // TODO: change to an enum that is either the state for compilation or the state for proving ([WitnessGeneration])
        // TODO: change the name to `runner` everywhere?
        sys: &mut RunState<ScalarField<Self::Curve>>,
        public_input: Self::PublicInput,
        private_input: Option<&Self::PrivateInput>,
    ) -> SnarkyResult<Self::PublicOutput>;

    /// Compiles the circuit to a prover index ([ProverIndexWrapper]) and a verifier index ([VerifierIndexWrapper]).
    fn compile_to_indexes(
        self,
    ) -> SnarkyResult<(ProverIndexWrapper<Self>, VerifierIndexWrapper<Self>)>
    where
        <Self::Curve as AffineCurve>::BaseField: PrimeField,
    {
        let compiled_circuit = compile(self)?;

        // create constraint system
        let cs = ConstraintSystem::create(compiled_circuit.gates.clone())
            .public(compiled_circuit.public_input_size)
            .build()
            .unwrap();

        // create SRS (for vesta, as the circuit is in Fp)
        // let mut srs = SRS::<Self::Curve>::create(cs.domain.d1.size as usize);
        let mut srs = <<Self::Proof as OpenProof<Self::Curve>>::SRS as SRS<Self::Curve>>::create(
            cs.domain.d1.size as usize,
        );
        srs.add_lagrange_basis(cs.domain.d1);
        let srs = std::sync::Arc::new(srs);

        debug!("using an SRS of size {}", srs.size());

        // create indexes
        let endo_q = <<Self as SnarkyCircuit>::Curve as KimchiCurve>::other_curve_endo();

        let prover_index =
            crate::prover_index::ProverIndex::<Self::Curve, Self::Proof>::create(cs, *endo_q, srs);
        let verifier_index = prover_index.verifier_index();

        let prover_index = ProverIndexWrapper {
            compiled_circuit,
            index: prover_index,
        };

        let verifier_index = VerifierIndexWrapper {
            index: verifier_index,
        };

        Ok((prover_index, verifier_index))
    }
}
