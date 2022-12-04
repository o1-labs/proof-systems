use crate::writer::{Cs, GateSpec, System, Var, WitnessGenerator};
use ark_ec::AffineCurve;
use ark_ff::{One, PrimeField, Zero};
use commitment_dlog::{
    commitment::CommitmentCurve,
    srs::{endos, SRS},
};
use kimchi::{
    circuits::{constraints::ConstraintSystem, gate::GateType},
    curve::KimchiCurve,
    plonk_sponge::FrSponge,
    proof::ProverProof,
    prover_index::ProverIndex,
};
use mina_poseidon::FqSponge;

/// Given an index, a group map, a public input vector, and a circuit `main`, it creates a proof.
///
/// # Panics
///
/// Will panic if recursive proof creation returns `ProverError`.
pub fn prove<G, H, EFqSponge, EFrSponge>(
    index: &ProverIndex<G>,
    group_map: &G::Map,
    public_input: Vec<G::ScalarField>,
    mut main: H,
) -> ProverProof<G>
where
    H: FnMut(&mut WitnessGenerator<G::ScalarField>, Vec<Var<G::ScalarField>>),
    G::BaseField: PrimeField,
    G: KimchiCurve,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
{
    // create the witness generator
    let mut gen: WitnessGenerator<G::ScalarField> = WitnessGenerator::new(&public_input);

    // run the witness generation
    let public_vars = public_input
        .iter()
        .map(|x| Var {
            index: 0,
            value: Some(*x),
        })
        .collect();
    main(&mut gen, public_vars);

    // get the witness columns
    gen.curr_gate_count();
    let columns = gen.columns();

    // create the proof
    ProverProof::create_recursive::<EFqSponge, EFrSponge>(group_map, columns, &[], index, vec![])
        .unwrap()
}

/// Creates the prover index on input an `srs`, used `constants`, parameters for Poseidon, number of public inputs, and a specific circuit
///
/// # Panics
///
/// Will panic if `constraint_system` is not built with `public` input.
pub fn generate_prover_index<Curve, Circuit>(
    srs: std::sync::Arc<SRS<Curve>>,
    public: usize,
    main: Circuit,
) -> ProverIndex<Curve>
where
    Circuit: FnOnce(&mut System<Curve::ScalarField>, Vec<Var<Curve::ScalarField>>),
    Curve: KimchiCurve,
{
    let mut system: System<Curve::ScalarField> = System::default();
    let z = Curve::ScalarField::zero();

    // create public input variables
    let public_input_row = vec![Curve::ScalarField::one(), z, z, z, z, z, z, z, z, z];
    let public_input: Vec<_> = (0..public)
        .map(|_| {
            let v = system.var(|| panic!("fail"));

            system.gate(GateSpec {
                typ: GateType::Generic,
                row: vec![Some(v)],
                coeffs: public_input_row.clone(),
            });
            v
        })
        .collect();

    main(&mut system, public_input);

    let gates = system.gates();

    // Other base field = self scalar field
    let (endo_q, _endo_r) = endos::<Curve::OtherCurve>();
    //let (endo_q, _endo_r) = Curve::endos();

    let constraint_system = ConstraintSystem::<Curve::ScalarField>::create(gates)
        .public(public)
        .build()
        // TODO: return a Result instead of panicking
        .expect("couldn't construct constraint system");

    ProverIndex::<Curve>::create(constraint_system, endo_q, srs)
}

/// Handling coordinates in an affine curve
pub trait CoordinateCurve: AffineCurve {
    /// Returns the coordinates in the curve as two points of the base field
    fn to_coords(&self) -> Option<(Self::BaseField, Self::BaseField)>;
}

impl<G: CommitmentCurve> CoordinateCurve for G {
    fn to_coords(&self) -> Option<(Self::BaseField, Self::BaseField)> {
        CommitmentCurve::to_coordinates(self)
    }
}
