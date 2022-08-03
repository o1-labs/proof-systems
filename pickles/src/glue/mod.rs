use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};

use circuit_construction::{Cs, Constants, Cycle};

use commitment_dlog::srs::SRS;

use crate::types::{VarPoint, VarPolyComm};

use crate::kimchi::index::Index;

use crate::context::{Context, finalize};

/// Adds the nessary constraints for recursion to each constraint system
/// 
pub fn recursion<C, Cp, Cr>(
    cp: Cp, // application logic included (Step side)
    cr: Cr, // empty circuit (no other logic) (Wrap side)
    fan_in: usize, // number of proofs which can be ingested (at least 1 for recursion), Fr fan-in is always 1
    consts_fp: Constants<C::InnerField>,
    consts_fr: Constants<C::OuterField>,
    srs: &SRS<C::Outer>,
    domain: Domain<C::InnerField>,
    fp_proof_p_comm: &VarPolyComm<C::Outer, 1>, // the commitment to the public input of the proof verified on the Fr side
) where
    C: Cycle,
    Cp: Cs<C::InnerField>, // Step proof system
    Cr: Cs<C::OuterField>, // Wrap proof system
{
    assert!(fan_in > 1, "Fp fan-in must be >= 1 for recursion");

    // create context 
    let mut ctx = Context::new(
        cp,
        cr,
        consts_fp,
        consts_fr
    );

    // add Kimchi verifiers on Step side (for antecedents)

    // flip context (role of Fp and Fr)
    let mut ctx = ctx.flipped();

    // add single Kimchi verifier on Wrap side (just for immediately recursing on the Fp proof)   
    let fp_p_comm = unimplemented!();

    let index: Index<C::Outer> = unimplemented!();

    /*
    index::Index::verify(
        &mut ctx,
        p_comm: Msg<VarPolyComm<G, 1>>,
        inputs: &PublicInput<G>, // commitment to public input
        proof: VarProof<G, 2>,
    )
    */

    // flip context (role of Fp and Fr) again
    let mut ctx = ctx.flipped();

    // enforce equality between Wrap side public inputs and deferred values
    finalize::<C, Cp, Cr>(ctx, srs, domain, fp_p_comm);
}