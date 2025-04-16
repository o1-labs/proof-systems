use crate::{
    challenge::{ChallengeTerm, Challenges},
    column::E,
    curve::ArrabbiataCurve,
    interpreter::InterpreterEnv,
    setup2::IndexedRelation,
    witness2::Env,
    MAX_DEGREE, MV_POLYNOMIAL_ARITY, NUMBER_OF_COLUMNS,
};
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use ark_poly::Evaluations;
use mvpoly::{monomials::Sparse, MVPoly};
use num_bigint::BigInt;
use poly_commitment::{commitment::CommitmentCurve, PolyComm};
use std::{collections::HashMap, hash::Hash};

pub mod minroot;
pub mod verifiable_minroot;
pub mod verifier;
pub mod verifier_stateful;

/// A ZkApp is a (stateless) program that can be executed and proven using a
/// (zero-knowledge) succinct non-interactive argument of knowledge or in short
/// a zkSNARK. In particular, the interface is designed to be used with the
/// Arrabbiata accumulation scheme and its corresponding decider.
///
/// A ZkApp is defined over a list of instructions (of type
/// [Self::Instruction]), where each instruction is a step of the computation.
/// The computation is defined by the control-flow of the ZkApp, which is
/// defined by the methods [Self::fetch_next_instruction] and
/// [Self::fetch_instruction].
/// An instruction is considered to be filling only one row of the execution
/// trace.
///
/// A list of instructions sharing the same constraints is called a gadget (of
/// type [Self::Gadget]). Each instruction must be convertible to a gadget,
/// therefore the type restriction to [From<Self::Instruction>]. It will be used
/// in particular by the method [setup] to build the list of selectors.
///
/// An instruction can also transport some data, which can be used to guide the
/// control-flow and to provide additional information to the interpreter while
/// executing [Self::run].
/// For instance, a gadget could be `EllipticCurveScaling`, which could be
/// formed by a set of instructions `EllipticCurveScaling(bit)` where `bit`
/// defines the bit of the scalar that is being processed.
///
/// More specialised ZkApp's can be implemented with this interface.
/// For instance, a [VerifierApp] is a ZkApp that is designed to implement the
/// verifier part of the accumulation scheme.
/// Naturally, it has to implement the ZkApp trait.
///
/// Another kind of ZkApp is a [VerifiableZkApp], which is a ZkApp that is
/// designed to be verifiable with a [VerifierApp], i.e., it is designed to be
/// accompanied by a verifier.
pub trait ZkApp<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    type Instruction: Copy;

    type Gadget: From<Self::Instruction> + Eq + Hash;

    /// Fetch the first instruction to execute.
    fn fetch_instruction(&self) -> Self::Instruction;

    /// Describe the control-flow of the ZkApp.
    /// This function should return the next instruction to execute after
    /// `current_instr`.
    ///
    /// If the current instruction is the last one, it should return `None`.
    ///
    /// The method is going to be called by the [execute] function and [setup]
    /// function.
    fn fetch_next_instruction(&self, current_instr: Self::Instruction)
        -> Option<Self::Instruction>;

    /// Execute the instruction `instr` over the interpreter environment `E`.
    ///
    /// The interpreter environment is responsible to keep track of the
    /// execution trace, and to provide the necessary values to the ZkApp.
    ///
    /// The method is going to be called by the [execute] function, which is
    /// responsible to build the whole execution trace, instruction by
    /// instruction. The stoppingcondition is when the
    /// [Self::fetch_next_instruction] returns `None`.
    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction);
}

/// A VerifierApp is a ZkApp that is designed to implement the verifier part of
/// the accumulation scheme.
///
/// The verifier is responsible to check the validity of a previously generated
/// proof.
///
/// Naturally, it has to implement the ZkApp trait, as it is a program that can
/// be accumulated.
pub trait VerifierApp<C>: ZkApp<C> + Copy + Clone + Hash + Eq + PartialEq
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
}

/// A VerifiableZkApp is a ZkApp that is designed to be verifiable with a
/// [VerifierApp], i.e., it is designed to be accompanied by a verifier.
///
/// An example of a [VerifiableZkApp] is the [verifiable_minroot::MinRoot] ZkApp
/// that uses the vanilla Arrabbiata verifier [verifier::Verifier].
pub trait VerifiableZkApp<C>: ZkApp<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    type Verifier: VerifierApp<C>;
}

/// Execute the ZkApp `zkapp` over the interpreter environment `env`.
/// This is a generic function that can be used to execute any ZkApp.
///
/// This method will build the execution trace of the ZkApp, instruction by
/// instruction. The stopping condition is when the
/// [Self::fetch_next_instruction] returns `None`.
///
/// This method must be used in conjunction with the [prove_step] method to
/// build the accumulation proof.
pub fn execute<E, C, Z>(zkapp: &Z, env: &mut E)
where
    E: InterpreterEnv,
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(env, i);
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
}

/// Create a setup for the ZkApp.
///
/// The setup will define the shape of the execution trace.
/// It is mostly consisting of the list of selectors that are used to select the
/// columns that are used in the computation, and how constrained they are.
///
/// For now, the concept of gadget and selectors are mixed together. We
/// should separate them in the future to allow more flexibility.
pub fn setup<C, Z>(zkapp: &Z) -> Vec<Z::Gadget>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut circuit: Vec<Z::Gadget> = vec![];
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        circuit.push(Z::Gadget::from(i));
        instr = zkapp.fetch_next_instruction(i);
    }
    circuit
}

/// Get the constraints per gadget for the ZkApp `zkapp`.
/// The constraints are the polynomials that are used to define the execution
/// trace.
///
/// The hypothesis is that each instruction of the ZkApp gives the same
/// constraints.
///
/// The output will contain all the constraints that would be used in a single
/// execution.
pub fn get_constraints_per_gadget<C, Z>(zkapp: &Z) -> HashMap<Z::Gadget, Vec<E<C::ScalarField>>>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut env = crate::constraint::Env::<C>::new();
    let mut constraints = HashMap::new();
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(&mut env, i);
        constraints.insert(Z::Gadget::from(i), env.constraints.clone());
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
    constraints
}

/// Get the constraints as [Sparse] polynomials per gadget for the ZkApp `zkapp`.
///
/// This method will be used to compute the cross-terms.
pub fn get_mvpoly_per_gadget<C, Z>(
    zkapp: &Z,
) -> HashMap<Z::Gadget, Vec<Sparse<C::ScalarField, { MV_POLYNOMIAL_ARITY }, { MAX_DEGREE }>>>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
    Z: ZkApp<C>,
{
    let mut env = crate::constraint::Env::<C>::new();
    let mut constraints = HashMap::new();
    let mut instr: Option<Z::Instruction> = Some(zkapp.fetch_instruction());
    while let Some(i) = instr {
        zkapp.run(&mut env, i);
        let polys: Vec<_> = env
            .constraints
            .iter()
            .map(|c| Sparse::from_expr(c.clone(), Some(NUMBER_OF_COLUMNS)))
            .collect::<Vec<_>>();
        constraints.insert(Z::Gadget::from(i), polys);
        env.reset();
        instr = zkapp.fetch_next_instruction(i);
    }
    constraints
}

/// Prove a step of the ZkApp `zkapp` over the interpreter environment `env`.
///
/// This method must be called after the [execute] method to build the
/// accumulation proof.
pub fn prove_step<Fp, Fq, C1, C2, Z1, Z2, E1, E2>(env1: &mut E1, env2: &mut E2)
where
    Fp: PrimeField,
    Fq: PrimeField,
    C1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    C2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    C1::BaseField: PrimeField,
    C2::BaseField: PrimeField,
    Z1: ZkApp<C1>,
    Z2: ZkApp<C2>,
    E1: Env<Fp, Fq, C1, C2, Z1>,
    E2: Env<Fq, Fp, C2, C1, Z2>,
{
    // We initialize the sponge with the last program digest.
    let domain_size = env1.domain.d1.size();
    let mut sponge = E1::create_new_sponge();
    E1::absorb_fq(&mut sponge, env1.last_program_digest_after_execution);
    // FIXME: update env2 with sponge state

    let cols_commitments = env1.witness.iter().map(|w| {
        let evals = Evaluations::from_vec_and_domain(w.clone(), env1.domain.d1);
        env1.srs
            .commit_evaluations_non_hiding(&evals, env1.domain.d1)
    });
    // FIXME: update env2
    E1::absorb_curve_points(&mut sponge, cols_commitments);

    let constraints_combiner = E1::squeeze_challenge(&mut sponge);
    // FIXME: update env2

    // compute_cross_terms(env, zkapp_state);
    let cts = {
        let cts: [Vec<Fp>; MAX_DEGREE] = core::array::from_fn(|_| {
            Vec::with_capacity(domain_size);
        });
        (0..domain_size).for_each(|row| {
            let next_row = (row + 1) % domain_size;

            let state_left: [E1::ScalarField; 2 * NUMBER_OF_COLUMNS] = core::array::from_fn(|i| {
                if i < NUMBER_OF_COLUMNS {
                    env1.accumulated_program_state[row][i]
                } else {
                    env1.accumulated_program_state[next_row][i - NUMBER_OF_COLUMNS]
                }
            });
            let state_right: [E1::ScalarField; 2 * NUMBER_OF_COLUMNS] = core::array::from_fn(|i| {
                if i < NUMBER_OF_COLUMNS {
                    env1.witness[row][i]
                } else {
                    env1.witness[next_row][i - NUMBER_OF_COLUMNS]
                }
            });

            let alpha_left =
                env1.verifier.accumulated_challenges[ChallengeTerm::ConstraintCombiner];
            let alpha_right = constraints_combiner.clone();

            let u_left = env1.verifier.accumulated_challenges[ChallengeTerm::ConstraintHomogenizer];
            let u_right = E1::ScalarField::one();
            // FIXME: add gadget
            let gadget = [Sparse::zero()];
            let cross_terms = mvpoly::compute_combined_cross_terms(
                gadget,
                &state_left,
                &state_right,
                &alpha_left,
                &alpha_right,
                &u_left,
                &u_right,
            );
            cross_terms.iter().for_each(|(power, term)| {
                cts[power].push(term.clone());
            });
        });
        cts
    };

    // Commit the cross-terms
    cts.iter().for_each(|ct| {
        let evals = Evaluations::from_vec_and_domain(ct.clone(), env1.domain.d1);
        env1.srs
            .commit_evaluations_non_hiding(&evals, env1.domain.d1)
    });
    // Absorb the cross-terms
    E1::absorb_curve_points(&mut sponge, cts);

    // Squeeze a challenge to accumulate the witnesses
    let constraint_homogenizer = E1::squeeze_challenge(&mut sponge);

    // Accumulate witnesses
    env1.accumulated_program_state = env1
        .accumulated_program_state
        .iter()
        .zip(env1.witness.iter())
        .map(|(acc, w)| acc + constraint_homogenizer * w)
        .collect();

    // domain_size values
    // computing ((r * 0) + ct[n]) * r + ct[n + 1] ...
    env1.accumulated_error = env1.accumulated_error.iter().enumerate().map(|(i, e_i)| {
        cts.rev().iter().fold(Fp::zero(), |acc, ct| {
            let ct_i = ct.get(i).unwrap_or(&Fp::zero());
            let res = acc * constraint_homogenizer + ct_i;
            res
        }) + e_i
    })
}

pub fn fold<Fp, Fq, C1, C2, Z1, Z2>(
    zkapp1: &Z1,
    zkapp2: &Z2,
    n: usize,
) -> (
    Env<C1::ScalarField, C2::ScalarField, C1, C2, Z1>,
    Env<C2::ScalarField, C1::ScalarField, C2, C1, Z2>,
)
where
    Fp: PrimeField,
    Fq: PrimeField,
    C1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    C2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    C1::BaseField: PrimeField,
    C2::BaseField: PrimeField,
    <<C1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<C2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    Z1: VerifiableZkApp<C1, Verifier = verifier_stateful::Verifier<C1>>,
    Z2: VerifiableZkApp<C2, Verifier = verifier_stateful::Verifier<C2>>,
{
    // FIXME:
    // "Augment" the function here, i.e. make them verifiable.
    // The type must still be `VerifiableZkApp`, with the same verifier because
    // the environment could be different.
    let srs_log2_size = 16;
    // FIXME: remove ZkApp types in the IndexedRelation to have something
    // FIXME: use only one type of ZkApp. It will ease this first version.
    let indexed_relation = IndexedRelation::new(zkapp1, zkapp2, srs_log2_size);
    let mut env1 = Env::<C1::ScalarField, C2::ScalarField, C1, C2, Z1>::new(indexed_relation);
    let mut env2 = Env::<C2::ScalarField, C1::ScalarField, C2, C1, Z2>::new(indexed_relation);
    let mut i = 0;
    while i < n {
        execute(zkapp1, &mut env1);
        // Proving a step will take elements of the env1, and update the second
        // environment that will use the output of the first one.
        prove_step(&mut env1, &mut env2);
        env1.reset_for_next_iteration();

        execute(zkapp2, &mut env2);
        prove_step(&mut env2, &mut env1);
        env2.reset_for_next_iteration();

        i += 1;
    }
    (env1, env2)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::decider;
    use ark_ff::UniformRand;
    use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};

    #[test]
    fn test_minroot_fold() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let zkapp1: verifiable_minroot::MinRoot<Vesta> = {
            let x = Fp::rand(&mut rng);
            let y = Fp::rand(&mut rng);
            let n = 1000;
            verifiable_minroot::MinRoot::<Vesta>::new(x, y, n)
        };
        let zkapp2: verifiable_minroot::MinRoot<Pallas> = {
            let x = Fq::rand(&mut rng);
            let y = Fq::rand(&mut rng);
            let n = 1000;
            verifiable_minroot::MinRoot::<Pallas>::new(x, y, n)
        };

        // Fold 1000 times both zkapps
        let res = fold(&zkapp1, &zkapp2, 1000);
        let proof = decider::prover::prove(&res);
        let verify = decider::verifier::verify(&res.indexed_relation, &proof.unwrap());
        assert!(verify.is_ok());
    }
}
