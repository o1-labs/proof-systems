//! This is the pickles flavor of the o1vm.
//! The goal of this flavor is to run a version of the o1vm with selectors for
//! each instruction using the Pasta curves and the IPA PCS.
//!
//! A proof is generated for each set of N continuous instructions, where N is
//! the size of the supported SRS. The proofs will then be aggregated using
//! a modified version of pickles.
//!
//! You can run this flavor by using:
//!
//! ```bash
//! O1VM_FLAVOR=pickles bash run-code.sh
//! ```

use std::time::Instant;

use self::proof::ProofInputs;
use crate::{
    cannon::{self, Start},
    interpreters::mips::{
        column::N_MIPS_REL_COLS, constraints as mips_constraints, witness as mips_witness,
        Instruction,
    },
    preimage_oracle::PreImageOracleT,
};
use ark_ff::UniformRand;
use kimchi::circuits::domains::EvaluationDomains;
use kimchi_msm::expr::E;
use log::debug;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use once_cell::sync::Lazy;
use poly_commitment::ipa::SRS;
use rand::rngs::ThreadRng;

pub mod column_env;
pub mod proof;
pub mod prover;
pub mod verifier;

/// Maximum degree of the constraints.
/// It does include the additional degree induced by the multiplication of the
/// selectors.
pub const MAXIMUM_DEGREE_CONSTRAINTS: u64 = 6;

/// Degree of the quotient polynomial. We do evaluate all polynomials on d8
/// (because of the value of [MAXIMUM_DEGREE_CONSTRAINTS]), and therefore, we do
/// have a degree 7 for the quotient polynomial.
/// Used to keep track of the number of chunks we do have when we commit to the
/// quotient polynomial.
pub const DEGREE_QUOTIENT_POLYNOMIAL: u64 = 7;

/// Total number of constraints for all instructions, including the constraints
/// added for the selectors.
pub const TOTAL_NUMBER_OF_CONSTRAINTS: usize = 464;

pub const DOMAIN_SIZE: usize = 1 << 15;

pub static DOMAIN_FP: Lazy<EvaluationDomains<Fp>> =
    Lazy::new(|| EvaluationDomains::<Fp>::create(DOMAIN_SIZE).unwrap());

fn prove_and_verify(
    srs: &SRS<Vesta>,
    curr_proof_inputs: ProofInputs<Vesta>,
    constraints: &[E<Fp>],
    rng: &mut ThreadRng,
) {
    let start_iteration = Instant::now();
    let proof = prover::prove::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
        _,
    >(*DOMAIN_FP, srs, curr_proof_inputs, constraints, rng)
    .unwrap();

    debug!(
        "Proof generated in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    let verif = verifier::verify::<
        Vesta,
        DefaultFqSponge<VestaParameters, PlonkSpongeConstantsKimchi>,
        DefaultFrSponge<Fp, PlonkSpongeConstantsKimchi>,
    >(*DOMAIN_FP, srs, constraints, &proof);
    debug!(
        "Verification done in {elapsed} μs",
        elapsed = start_iteration.elapsed().as_micros()
    );
    assert!(verif);
}

pub fn cannon_main(
    configuration: cannon::VmConfiguration,
    mut mips_wit_env: mips_witness::Env<Fp, Box<dyn PreImageOracleT>>,
    srs: &SRS<Vesta>,
    start: Start,
    meta: &Option<cannon::Meta>,
) {
    let mut rng = rand::thread_rng();

    let constraints = mips_constraints::get_all_constraints::<Fp>();

    let mut curr_proof_inputs: ProofInputs<Vesta> = ProofInputs::new(DOMAIN_SIZE);
    while !mips_wit_env.halt {
        let _instr: Instruction = mips_wit_env.step(&configuration, meta, &start);
        for (scratch, scratch_chunk) in mips_wit_env
            .scratch_state
            .iter()
            .zip(curr_proof_inputs.evaluations.scratch.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        for (scratch, scratch_chunk) in mips_wit_env
            .scratch_state_inverse
            .iter()
            .zip(curr_proof_inputs.evaluations.scratch_inverse.iter_mut())
        {
            scratch_chunk.push(*scratch);
        }
        curr_proof_inputs
            .evaluations
            .instruction_counter
            .push(Fp::from(mips_wit_env.instruction_counter));
        // FIXME: Might be another value
        curr_proof_inputs.evaluations.error.push(Fp::rand(&mut rng));

        curr_proof_inputs
            .evaluations
            .selector
            .push(Fp::from((mips_wit_env.selector - N_MIPS_REL_COLS) as u64));

        if curr_proof_inputs.evaluations.instruction_counter.len() == DOMAIN_SIZE {
            debug!("Limit of {DOMAIN_SIZE} reached. We make a proof, verify it (for testing) and start with a new chunk");
            prove_and_verify(srs, curr_proof_inputs, &constraints, &mut rng);
            curr_proof_inputs = ProofInputs::new(DOMAIN_SIZE);
        }
    }
    if curr_proof_inputs.evaluations.instruction_counter.len() < DOMAIN_SIZE {
        debug!("Reached halting condition, proving remaining execution");
        curr_proof_inputs.pad();
        prove_and_verify(srs, curr_proof_inputs, &constraints, &mut rng);
    }
}

#[cfg(test)]
mod tests;
