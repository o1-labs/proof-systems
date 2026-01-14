//! This module implements the core folding/accumulation logic for the Arrabbiata
//! IVC scheme.
//!
//! The folding scheme combines two relaxed R1CS-like instances into a single
//! accumulated instance. For high-degree constraints (degree > 2), this requires
//! computing cross-terms that capture the interaction between the two instances.
//!
//! ## Cross-terms
//!
//! For a constraint polynomial P of degree D, when we fold two instances with
//! a random challenge r, the cross-terms are the coefficients of r^1, r^2, ..., r^{D-1}
//! in the expansion of P(acc + r * fresh).
//!
//! ## Error term accumulation
//!
//! The error term is a per-row polynomial that accumulates the "slack" from
//! folding relaxed instances. It follows:
//! ```text
//! e_new[i] = e_acc[i] + sum_{j=1}^{D-1}(r^j * t_j[i]) + r^D * e_fresh[i]
//! ```

use ark_ff::PrimeField;
use mvpoly::monomials::Sparse;
use std::collections::HashMap;

use crate::{column::Gadget, MAX_DEGREE, MV_POLYNOMIAL_ARITY};

/// Cross-terms computed during the folding process.
///
/// For a constraint of degree D, we have D-1 cross-term polynomials,
/// corresponding to the coefficients of r^1, r^2, ..., r^{D-1}.
#[derive(Debug, Clone)]
pub struct CrossTerms<F: PrimeField> {
    /// Cross-term polynomials indexed by power of r.
    /// Key: power (1 to MAX_DEGREE - 1)
    /// Value: polynomial evaluations (one per row)
    pub terms: HashMap<usize, Vec<F>>,
}

impl<F: PrimeField> CrossTerms<F> {
    /// Create a new CrossTerms structure with zero-initialized polynomials.
    pub fn new(domain_size: usize) -> Self {
        let mut terms = HashMap::new();
        // Cross-terms are for powers 1 to MAX_DEGREE (inclusive, due to homogenization)
        for power in 1..=MAX_DEGREE {
            terms.insert(power, vec![F::zero(); domain_size]);
        }
        CrossTerms { terms }
    }

    /// Get the cross-term polynomial for a given power of r.
    pub fn get(&self, power: usize) -> Option<&Vec<F>> {
        self.terms.get(&power)
    }

    /// Get mutable reference to cross-term polynomial for a given power.
    pub fn get_mut(&mut self, power: usize) -> Option<&mut Vec<F>> {
        self.terms.get_mut(&power)
    }

    /// Set the value at a specific row for a given power.
    pub fn set(&mut self, power: usize, row: usize, value: F) {
        if let Some(poly) = self.terms.get_mut(&power) {
            poly[row] = value;
        }
    }

    /// Add a value to the existing value at a specific row for a given power.
    pub fn add(&mut self, power: usize, row: usize, value: F) {
        if let Some(poly) = self.terms.get_mut(&power) {
            poly[row] += value;
        }
    }
}

/// Compute cross-terms for a single row given the active gadget's constraints.
///
/// This function computes the cross-terms for one row of the execution trace,
/// using the constraints associated with the currently active gadget.
///
/// # Arguments
/// * `constraints` - The constraint polynomials for the active gadget
/// * `eval_acc` - Evaluation point from accumulated instance (witness values)
/// * `eval_fresh` - Evaluation point from fresh instance (new witness values)
/// * `u_acc` - Homogenization variable for accumulated instance
/// * `u_fresh` - Homogenization variable for fresh instance
/// * `alpha_acc` - Constraint combiner for accumulated instance
/// * `alpha_fresh` - Constraint combiner for fresh instance
///
/// # Returns
/// A HashMap mapping power of r to the cross-term coefficient for that power.
pub fn compute_cross_terms_for_row<F: PrimeField>(
    constraints: &[Sparse<F, MV_POLYNOMIAL_ARITY, MAX_DEGREE>],
    eval_acc: &[F; MV_POLYNOMIAL_ARITY],
    eval_fresh: &[F; MV_POLYNOMIAL_ARITY],
    u_acc: F,
    u_fresh: F,
    alpha_acc: F,
    alpha_fresh: F,
) -> HashMap<usize, F> {
    // Use mvpoly's compute_combined_cross_terms function
    mvpoly::compute_combined_cross_terms(
        constraints.to_vec(),
        *eval_acc,
        *eval_fresh,
        u_acc,
        u_fresh,
        alpha_acc,
        alpha_fresh,
    )
}

/// Compute all cross-terms for the entire circuit.
///
/// This function iterates over all rows in the domain, retrieves the active
/// gadget's constraints for each row, and computes the cross-terms.
///
/// # Arguments
/// * `constraints` - All constraints indexed by gadget
/// * `selectors` - The gadget selector for each row
/// * `witness_acc` - Accumulated witness (columns × rows)
/// * `witness_fresh` - Fresh witness (columns × rows)
/// * `u_acc` - Homogenization variable for accumulated instance
/// * `u_fresh` - Homogenization variable for fresh instance
/// * `alpha_acc` - Constraint combiner for accumulated instance
/// * `alpha_fresh` - Constraint combiner for fresh instance
///
/// # Returns
/// CrossTerms containing all cross-term polynomials.
pub fn compute_all_cross_terms<F: PrimeField>(
    constraints: &HashMap<Gadget, Vec<Sparse<F, MV_POLYNOMIAL_ARITY, MAX_DEGREE>>>,
    selectors: &[Gadget],
    witness_acc: &[Vec<F>],
    witness_fresh: &[Vec<F>],
    u_acc: F,
    u_fresh: F,
    alpha_acc: F,
    alpha_fresh: F,
) -> CrossTerms<F> {
    let domain_size = selectors.len();
    let mut cross_terms = CrossTerms::new(domain_size);

    for row in 0..domain_size {
        let next_row = (row + 1) % domain_size;

        // Get the active gadget for this row
        let gadget = selectors[row];

        // Skip NoOp gadgets - they have no constraints
        if gadget == Gadget::NoOp {
            continue;
        }

        // Get constraints for this gadget
        let gadget_constraints = match constraints.get(&gadget) {
            Some(c) => c,
            None => continue, // No constraints for this gadget
        };

        // Build evaluation arrays for accumulated and fresh instances
        // Layout: [col_0_curr, col_1_curr, ..., col_14_curr, col_0_next, col_1_next, ..., col_14_next]
        let mut eval_acc: [F; MV_POLYNOMIAL_ARITY] = [F::zero(); MV_POLYNOMIAL_ARITY];
        let mut eval_fresh: [F; MV_POLYNOMIAL_ARITY] = [F::zero(); MV_POLYNOMIAL_ARITY];

        for col in 0..crate::NUMBER_OF_COLUMNS {
            // Current row values
            eval_acc[col] = witness_acc[col][row];
            eval_fresh[col] = witness_fresh[col][row];

            // Next row values (offset by NUMBER_OF_COLUMNS)
            eval_acc[crate::NUMBER_OF_COLUMNS + col] = witness_acc[col][next_row];
            eval_fresh[crate::NUMBER_OF_COLUMNS + col] = witness_fresh[col][next_row];
        }

        // Compute cross-terms for this row
        let row_cross_terms = compute_cross_terms_for_row(
            gadget_constraints,
            &eval_acc,
            &eval_fresh,
            u_acc,
            u_fresh,
            alpha_acc,
            alpha_fresh,
        );

        // Store the results
        for (power, value) in row_cross_terms {
            cross_terms.set(power, row, value);
        }
    }

    cross_terms
}

/// Fold two witness polynomials together.
///
/// Computes: w_new = w_acc + r * w_fresh
///
/// # Arguments
/// * `witness_acc` - Accumulated witness (columns × rows)
/// * `witness_fresh` - Fresh witness (columns × rows)
/// * `r` - Folding challenge
///
/// # Returns
/// The folded witness.
pub fn fold_witnesses<F: PrimeField>(
    witness_acc: &[Vec<F>],
    witness_fresh: &[Vec<F>],
    r: F,
) -> Vec<Vec<F>> {
    witness_acc
        .iter()
        .zip(witness_fresh.iter())
        .map(|(col_acc, col_fresh)| {
            col_acc
                .iter()
                .zip(col_fresh.iter())
                .map(|(acc, fresh)| *acc + r * fresh)
                .collect()
        })
        .collect()
}

/// Fold two error term polynomials together, incorporating cross-terms.
///
/// Computes: e_new[i] = e_acc[i] + sum_{j=1}^{D-1}(r^j * t_j[i]) + r^D * e_fresh[i]
///
/// # Arguments
/// * `error_acc` - Accumulated error term polynomial
/// * `error_fresh` - Fresh error term polynomial
/// * `cross_terms` - Cross-terms from folding
/// * `r` - Folding challenge
///
/// # Returns
/// The folded error term polynomial.
pub fn fold_error_terms<F: PrimeField>(
    error_acc: &[F],
    error_fresh: &[F],
    cross_terms: &CrossTerms<F>,
    r: F,
) -> Vec<F> {
    let domain_size = error_acc.len();
    let mut result = vec![F::zero(); domain_size];

    // Precompute powers of r
    let mut r_powers: Vec<F> = vec![F::one()];
    for _ in 1..=MAX_DEGREE {
        r_powers.push(*r_powers.last().unwrap() * r);
    }

    for row in 0..domain_size {
        // Start with accumulated error
        let mut value = error_acc[row];

        // Add cross-terms: sum_{j=1}^{D-1}(r^j * t_j[row])
        // Note: we use `power` both as index into r_powers and key for cross_terms.get()
        #[allow(clippy::needless_range_loop)]
        for power in 1..=MAX_DEGREE {
            if let Some(cross_term_poly) = cross_terms.get(power) {
                value += r_powers[power] * cross_term_poly[row];
            }
        }

        // Add r^D * e_fresh[row]
        value += r_powers[MAX_DEGREE] * error_fresh[row];

        result[row] = value;
    }

    result
}

/// Fold two challenges together.
///
/// Computes: chal_new = chal_acc + r * chal_fresh
pub fn fold_challenge<F: PrimeField>(chal_acc: F, chal_fresh: F, r: F) -> F {
    chal_acc + r * chal_fresh
}

/// Fold the homogenization variable.
///
/// Computes: u_new = u_acc + r * u_fresh
pub fn fold_homogenizer<F: PrimeField>(u_acc: F, u_fresh: F, r: F) -> F {
    u_acc + r * u_fresh
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_cross_terms_new() {
        let domain_size = 256;
        let cross_terms: CrossTerms<Fp> = CrossTerms::new(domain_size);

        // Check that we have entries for powers 1 to MAX_DEGREE
        for power in 1..=MAX_DEGREE {
            assert!(cross_terms.get(power).is_some());
            assert_eq!(cross_terms.get(power).unwrap().len(), domain_size);
        }
    }

    #[test]
    fn test_fold_witnesses() {
        let witness_acc: Vec<Vec<Fp>> = vec![
            vec![
                Fp::from(1u64),
                Fp::from(2u64),
                Fp::from(3u64),
                Fp::from(4u64),
            ],
            vec![
                Fp::from(5u64),
                Fp::from(6u64),
                Fp::from(7u64),
                Fp::from(8u64),
            ],
        ];

        let witness_fresh: Vec<Vec<Fp>> = vec![
            vec![
                Fp::from(10u64),
                Fp::from(20u64),
                Fp::from(30u64),
                Fp::from(40u64),
            ],
            vec![
                Fp::from(50u64),
                Fp::from(60u64),
                Fp::from(70u64),
                Fp::from(80u64),
            ],
        ];

        let r = Fp::from(2u64);
        let result = fold_witnesses(&witness_acc, &witness_fresh, r);

        // Check: result[col][row] = acc[col][row] + r * fresh[col][row]
        assert_eq!(result[0][0], Fp::from(1u64 + 2 * 10u64)); // 21
        assert_eq!(result[0][1], Fp::from(2u64 + 2 * 20u64)); // 42
        assert_eq!(result[1][0], Fp::from(5u64 + 2 * 50u64)); // 105
    }

    #[test]
    fn test_fold_challenge() {
        let acc = Fp::from(10u64);
        let fresh = Fp::from(5u64);
        let r = Fp::from(3u64);

        let result = fold_challenge(acc, fresh, r);
        assert_eq!(result, Fp::from(10u64 + 3 * 5u64)); // 25
    }
}
