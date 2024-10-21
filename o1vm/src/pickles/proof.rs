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
        let mut met = false;
        let mut fst_met = 666;
        for i in 0..self.evaluations.selector.len() {
            if !met {
                met = <G::ScalarField as Field>::ONE == self.evaluations.selector[i];
                if met {
                    fst_met = i
                }
            }
        }
        let l = vec![16, 18, 19, 20, 21];
        if !met {
            // println!("no instr 17 found")
        } else {
            println!("fst instr 17 is {}", fst_met);
            for i in l {
                println!("scratch[{}]= {}", i, self.evaluations.scratch[i][fst_met])
            }
            let x = self.evaluations.scratch[16][fst_met]
                - G::ScalarField::from((8 + 16 + 16 * 256) as u64);
            let inv_or_zero = self.evaluations.scratch[21][fst_met];
            if x * inv_or_zero == -G::ScalarField::ONE {
                println!("!!!!!!!!")
            }
            if x * inv_or_zero == G::ScalarField::ONE {
                println!("111111111111111")
            }
            if x * inv_or_zero == G::ScalarField::ZERO {
                println!("000000000000")
            } else {
                println!("x*x_inv={}", x * inv_or_zero)
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
