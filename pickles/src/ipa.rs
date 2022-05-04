/// Inner-Product Argument Accumulator.
/// 
/// An implementation of the verifier for PC_DL from 
/// "Proof-Carrying Data from Accumulation Schemes", Section 2.4.1 and Appendix A (p. 49)
/// https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2020/499&version=20200929:225643&file=499.pdf
/// 
/// Note that verifying the accumulation requires two proofs,
/// because it involves both group operations over the base field and 
/// the invocation of a "random oracle" to produce elements of the scalar field.
/// 
/// Example, the challenges are Fp scalars for a curve Ep(Fq): |Ep(Fq)| = p.
/// 
/// On Fq side (commitments are in Eq(Fp), circuits are over Fq):
/// 
///     A proof is needed over Fq: 
/// 
///         1. To enable Ep arithmetic: endo scaling on Ep.
///         2. To hash the transcript consisting of Fq elements:
///            The L_i, R_i \in Ep(Fq) points.
/// 
/// On Fp side (commitments are in Ep(Fq), circuits are over Fp):
///     
///     A proof is needed over Fp:
/// 
///         1. To enable efficiently computing the Poseidon Sponge (Random Oracle) 
///            to derive the Fp challenges.
///     
/// # Izaak question:
/// 
/// We need to sqeeze Fp-Sponge for every round: 
/// after applying the Fq-sponge to hash the group elements. How?
/// Show me the Pickles-Ocaml code for this.
/// 
struct Accumulator<F: PrimeField + FftField> {
    challenges: Vec<F> // challenges passed from "Fq" to "Fq", essentially pass-through
}