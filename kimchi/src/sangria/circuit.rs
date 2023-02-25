use ark_ff::PrimeField;

use crate::circuits::polynomials::generic::{CONSTANT_OFFSET, GENERIC_REGISTERS, MUL_OFFSET};
use crate::curve::KimchiCurve;
use crate::snarky::prelude::*;

use super::protocol;

// Data structures
//

pub struct CircuitCommit<F>
where
    F: PrimeField,
{
    x: CVar<F>,
    y: CVar<F>,
    point_at_infinity: Boolean<F>,
}

#[derive(Debug, SnarkyType)]
pub struct CircuitSangriaProof<G>
where
    G: KimchiCurve,
{
    t_commit: CircuitCommit<G::ScalarField>,
}

// TODO: implement a deriver for [SnarkyType]
impl<G> SnarkyType<G::ScalarField> for CircuitSangriaProof<G>
where
    G: KimchiCurve,
{
    type Auxiliary = ();

    type OutOfCircuit = protocol::SangriaProof<G>;

    const SIZE_IN_FIELD_ELEMENTS: usize = 3;

    fn to_cvars(&self) -> (Vec<CVar<F>>, Self::Auxiliary) {
        todo!()
    }

    fn from_cvars_unsafe(cvars: Vec<CVar<F>>, aux: Self::Auxiliary) -> Self {
        todo!()
    }

    fn check(&self, cs: &mut RunState<F>) {
        todo!()
    }

    fn constraint_system_auxiliary() -> Self::Auxiliary {
        todo!()
    }

    fn value_to_field_elements(value: &Self::OutOfCircuit) -> (Vec<F>, Self::Auxiliary) {
        todo!()
    }

    fn value_of_field_elements(fields: Vec<F>, aux: Self::Auxiliary) -> Self::OutOfCircuit {
        todo!()
    }
}

pub struct CircuitSangriaInstance<F>
where
    F: PrimeField,
{
    public_input: Vec<CVar<F>>,
    scaling_factor: CVar<F>,
    register_commitments: [CircuitCommit<F>; GENERIC_REGISTERS],
    slack_commitment: CircuitCommit<F>,
}

fn truncate_to_128<F>(value: CVar<F>) -> CVar<F>
where
    F: PrimeField,
{
    todo!()
}

pub struct DeferredComputation<F>
where
    F: PrimeField,
{
    computed_folded_u: CVar<F>,
    from_u1: CVar<F>,
    from_u2: CVar<F>,
    from_r: CVar<F>,
}

pub struct CircuitOption<F, T>
where
    F: PrimeField,
{
    set: Boolean<F>,
    val: T,
}

pub fn verifier_fold<G>(
    sys: &mut RunState<G::ScalarField>,
    instance1: CircuitSangriaInstance<G::ScalarField>,
    instance2: CircuitSangriaInstance<G::ScalarField>,
    proof: CircuitSangriaProof<G>,
    deferred: CircuitOption<G::ScalarField, DeferredComputation<G::ScalarField>>,
) -> (
    CircuitSangriaInstance<G::ScalarField>,
    DeferredComputation<G::ScalarField>,
)
where
    G: KimchiCurve,
{
    // absorb proof and get challenge
    let (challenge, _) = sys.poseidon(loc!(), (proof.t_commit.x, proof.t_commit.y));

    // TODO: challenge must be a scalar, so get 128 first bits?
    let challenge = truncate_to_128(challenge);

    // fold the public input
    // TODO: should be a commitment
    let r_pub2 = instance2.public_input.scale(sys, challenge);
    let public_input = instance1.public_input.add(sys, loc!(), r_pub2);

    // fold the scaling factor
    let scaling_factor: CVar<G::ScalarField> = sys.compute(loc!(), || {
        instance1.scaling_factor + (instance2.scaling_factor * challenge)
    });
    let deferred = DeferredComputation {
        computed_folded_u: scaling_factor,
        from_u1: instance1.scaling_factor,
        from_u2: instance2.scaling_factor,
        from_r: challenge,
    };

    // fold the register commitments
    let register_commitments = instance1
        .register_commitments
        .iter()
        .zip(&instance2.register_commitments)
        .map(|(c1, c2)| {
            let r_c2 = c2.scale(sys, challenge);
            c1.add(sys, loc!(), r_c2)
        })
        .collect::<Vec<_>>();

    // compute new E commitment
    

    // return new instance and deferred computation
    let folded_instance = CircuitSangriaInstance {
        public_input,
        scaling_factor: instance1.scaling_factor,
        register_commitments: instance1.register_commitments,
        slack_commitment: instance1.slack_commitment,
    };

    // return
    (folded_instance, deferred)
}
