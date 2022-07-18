use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as Domain};

use circuit_construction::{Cs, Cycle};

use commitment_dlog::srs::SRS;

use crate::types::{VarPoint, VarPolyComm};

use super::context::{Context};

/// Consumes the context and adds constrains to enforce
/// the correct "passing" between the two proofs.
///
/// This method is a bit magical and central to how recursion works.
/// At a high level, it creates circuits to ensure that the values "passed" between the two proofs are consistent.
///
/// To do so, it computes **the commitment** to the public inputs of the other side:
/// a polynomial commitment in Lagrange form.
pub fn finalize<C, Cp, Cr>(
    ctx: Context<C::InnerField, C::OuterField, Cp, Cr>,
    srs: &SRS<C::Outer>,
    domain: Domain<C::InnerField>,
    fp_proof_p_comm: &VarPolyComm<C::Outer, 1>, // the commitment to the public input of the proof verified on the Fr side
) -> ()
where
    C: Cycle,
    Cp: Cs<C::InnerField>, // Step proof system
    Cr: Cs<C::OuterField>, // Wrap proof system
{
    let mut ctx = ctx.inner.unwrap();

    // sanity check
    assert_eq!(
        ctx.fr.deferred.len(),
        ctx.fp.deferred.len(),
        "public inputs does not have the same length, cannot enforce bit-wise equality"
    );

    // fetch lagrange basis
    let basis = srs
        .lagrange_bases
        .get(&domain.size())
        .expect("SRS missing lagrange basis for domain");

    // compute each component of the commitment
    let mut components: Vec<VarPoint<C::Outer>> = Vec::new();
    for (g, input) in basis.iter().zip(ctx.fr.deferred) {
        components.push(VarPoint::from_fixed_base(
            &mut ctx.fr.cs,
            g,
            input.bits.clone(),
            input.size,
        ))
    }

    // add all components to obtain final p_comm
    let p_comm: Option<VarPolyComm<C::Outer, 1>> = components.pop().map(|mut pt0| {
        for pt in components {
            pt0 = pt0.add(&mut ctx.fr.cs, &pt);
        }
        pt0.into() // turn point to poly commitment
    });

    // enforce equality with public commitment to the proof being verified on the fr side (the fp proof)
    // i.e. the Kimchi verifier on the Wrap side!
    if let Some(p_comm) = p_comm {
        p_comm.eq(&mut ctx.fr.cs, fp_proof_p_comm);
    }
}
