use crate::interpreters::mips::{
    column::N_MIPS_SEL_COLS,
    interpreter::{SYSCALL_BRK, SYSCALL_CLONE},
};
use ark_ff::Field;
use kimchi::curve::KimchiCurve;
use poly_commitment::{ipa::OpeningProof, PolyComm};

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
                // count += 1;
                for j in &l {
                    println!("scratch[{}]= {}", j, self.evaluations.scratch[*j][i])
                }
                // x16 - 0xcd0f
                let x =
                    self.evaluations.scratch[16][i] - G::ScalarField::from((SYSCALL_BRK) as u64);
                let inv_or_zero = self.evaluations.scratch[19][i];
                println!("x*x_inv_or_zero cd0f cst={}", x * inv_or_zero);
                if x * inv_or_zero == -G::ScalarField::from(1 as u64) {
                    println!("is -1")
                }
                // x16 - 0x1810
                let x =
                    self.evaluations.scratch[16][i] - G::ScalarField::from((SYSCALL_CLONE) as u64);
                let inv_or_zero = self.evaluations.scratch[21][i];
                println!("x*x_inv 1810cst={}", x * inv_or_zero);
                if x * inv_or_zero == -G::ScalarField::from(1 as u64) {
                    println!("is -1")
                }
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
