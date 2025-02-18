use ark_ff::PrimeField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};

use super::AbstractState;

/// A user state that deals only with bytes
///
/// The encoding with this state will be a simple conversion of bytes to field
/// elements. One field element contains a single byte.
#[derive(Debug, Clone)]
pub struct SparseState {
    pub bytes: Vec<u8>,
}

impl AbstractState for SparseState {
    fn encoded_length(&self) -> usize {
        self.bytes.len()
    }

    fn encode<F: PrimeField>(
        &self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>> {
        // Encoding sparse state
        //                                                 here we use
        //                                                 Montgomery, so the Fp
        //                                                 value is NOT the
        //                                                 actual value between
        //                                                 0 and 255
        //                                                    |
        let mut evals: Vec<F> = self.bytes.iter().map(|b| F::from(*b as u64)).collect();
        // We pad to the next multiple of the domain size
        let current_length: usize = evals.len();
        let domain_size: usize = domain.size as usize;
        let padded_length_to_multiple_domain_size: usize =
            domain_size * ((current_length + domain_size - 1) / domain_size);
        let pad_length: usize = padded_length_to_multiple_domain_size - current_length;
        evals.extend(std::iter::repeat(F::zero()).take(pad_length));
        let splitted_evals: Vec<Vec<F>> = evals.chunks(domain_size).map(|c| c.to_vec()).collect();
        splitted_evals
            .into_iter()
            .map(|e| Evaluations::from_vec_and_domain(e, domain))
            .collect()
    }
}
