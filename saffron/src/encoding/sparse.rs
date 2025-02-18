use ark_ff::PrimeField;
use ark_poly::{Evaluations, Radix2EvaluationDomain};

use super::AbstractState;

/// A user state that deals only with bytes
///
/// The encoding with this state will be a simple conversion of bytes to field
/// elements. One field element contains a single byte.
// FIXME: in a real case scenario, the size of the state is fixed. Here we allow
// any size by using a vector. It is only for the example.
#[derive(Debug, Clone)]
pub struct SparseState {
    pub bytes: Vec<u8>,
}

impl<F: PrimeField> AbstractState<F> for SparseState {
    fn encoded_length(&self) -> usize {
        self.bytes.len()
    }

    fn encode(
        &self,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>> {
        // Encoding sparse state
        //                                                 here we use
        //                                                 Montgomery, so the Fp
        //                                                 value is NOT the
        //                                                 actual value between
        //                                                 0 and 255
        //                                               Only for the sake of
        //                                               simplicity, otherwise I
        //                                               would not have used
        //                                               Montgomery. You can
        //                                               simply divide the value
        //                                               by F::R if you want.
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

    // FIXME: we should enforce in the type the number of polynomials used to
    // encode, so we know that sub also return the same number of polys.
    fn sub(
        self,
        other: SparseState,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Evaluations<F, Radix2EvaluationDomain<F>>> {
        // Assert that they take the same size in memory.
        // FIXME: we should encode it in the size, but this sparse example is
        // just... an example. A real state would have a fixed size.
        // We encode to have the same memory layout
        let encoded_left = self.encode(domain);
        let encoded_right = other.encode(domain);
        // We compute the diff on the content of the "memory area" they are
        // saved into.
        encoded_left
            .iter()
            .zip(encoded_right.iter())
            .map(|(l, r)| r - l)
            .collect()
    }
}
