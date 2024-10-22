use ark_ff::Field;
use kimchi::curve::KimchiCurve;
use poly_commitment::{ipa::OpeningProof, PolyComm};

use crate::interpreters::mips::column::N_MIPS_SEL_COLS;

pub struct WitnessColumns<G, S> {
    pub scratch: [G; crate::interpreters::mips::witness::SCRATCH_SIZE],
    pub instruction_counter: G,
    pub error: G,
    pub selector: S,
}
pub struct ProofInputs<G: KimchiCurve> {
    pub evaluations: WitnessColumns<Vec<G::ScalarField>, Vec<G::ScalarField>>,
}

impl<G: KimchiCurve> ProofInputs<G> {
    pub fn new(domain_size: usize) -> Self {
        ProofInputs {
            evaluations: WitnessColumns {
                scratch: std::array::from_fn(|_| Vec::with_capacity(domain_size)),
                instruction_counter: Vec::with_capacity(domain_size),
                error: Vec::with_capacity(domain_size),
                selector: Vec::with_capacity(domain_size),
            },
        }
    }

    pub fn witness17(&self) {
        let l = vec![16, 18, 19, 20, 21];
        let mut count = 0;
        for i in 0..self.evaluations.selector.len() {
            if G::ScalarField::from(17 as u64) == self.evaluations.selector[i] && count < 5 {
                count += 1;
                for j in &l {
                    println!("scratch[{}]= {}", j, self.evaluations.scratch[*j][i])
                }
                // second equal

                let x = self.evaluations.scratch[16][i]
    // 0xcd0f
- G::ScalarField::from((13 + 12*16 + 15 * 256 * 16) as u64);
                let inv_or_zero = self.evaluations.scratch[19][i];
                println!("x*x_inv cd0f cst={}", x * inv_or_zero);

                let x = self.evaluations.scratch[16][i]
            // 0x1810
                - G::ScalarField::from((8 + 16 + 16 * 256) as u64);
                let inv_or_zero = self.evaluations.scratch[21][i];
                println!("x*x_inv 1810cst={}", x * inv_or_zero);
            }
        }
    }
}
// FIXME: should we blind the commitment?
pub struct Proof<G: KimchiCurve> {
    pub commitments: WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS]>,
    pub zeta_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    pub zeta_omega_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS]>,
    /// IPA opening proof
    pub opening_proof: OpeningProof<G>,
}
