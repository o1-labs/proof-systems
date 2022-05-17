use circuit_construction::{Constants, Cs};

use ark_ff::{FftField, PrimeField};

pub struct Ctx<C: Cs<F>, F: FftField + PrimeField> {
    pub cs: C,
    pub constants: Constants<F>,
}

/// A recursive context can enforce constraints on "both side".
///
///
/// It has a "current side" (a proof system over Fp)
/// and a "complement side" (a proof system over Fp).
///
/// This enables us to have the entire computation for the verification of the
/// PlonK proof and accumulation described together and "prodecuurally";
/// even though the verification is spread across two proof systems.
///
/// By "flipping" the context and applying the same set of constraints obtain
/// the full set of constraints for both sides.
///
/// This avoids writing the verifier twice: once for each side.
pub(crate) struct MutualContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub fp: Ctx<CsFp, Fp>,
    pub fr: Ctx<CsFr, Fr>,
}

impl<Fp, Fr, CsFp, CsFr> MutualContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub fn flip(self) -> MutualContext<Fr, Fp, CsFr, CsFp> {
        MutualContext {
            fp: self.fr,
            fr: self.fp,
        }
    }

}

impl <Fp, Fr, CsFp, CsFr> AsMut<CsFp> for MutualContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    fn as_mut(&mut self) -> &mut CsFp {
        &mut self.fp.cs
    }
}

