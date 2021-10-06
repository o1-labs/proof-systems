/*****************************************************************************************************************

This source file implements Posedon constraint polynomials.

*****************************************************************************************************************/

use crate::gate::{CurrOrNext, GateType};
use CurrOrNext::*;
use crate::gates::poseidon::*;
use crate::nolookup::constraints::ConstraintSystem;
use crate::nolookup::scalars::ProofEvaluations;
use crate::polynomial::WitnessOverDomains;
use crate::wires::COLUMNS;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use array_init::array_init;
use o1_utils::{ExtendedDensePolynomial, ExtendedEvaluations};
use oracle::poseidon::{sbox, ArithmeticSpongeParams, SpongeConstants, PlonkSpongeConstants15W};
use crate::expr::{E, Variable, Column, ConstantExpr as C, Cache};

/// An equation of the form `(curr | next)[i] = round(curr[j])`
pub struct RoundEquation {
    pub source: usize,
    pub target: (CurrOrNext, usize),
}

pub const ROUND_EQUATIONS: [RoundEquation; ROUNDS_PER_ROW] = [
    RoundEquation {
        source: 0,
        target: (Curr, 1),
    },
    RoundEquation {
        source: 1,
        target: (Curr, 2),
    },
    RoundEquation {
        source: 2,
        target: (Curr, 3),
    },
    RoundEquation {
        source: 3,
        target: (Curr, 4),
    },
    RoundEquation {
        source: 4,
        target: (Next, 0),
    },
];

/// poseidon quotient poly contribution computation `f^7 + c(x) - f(wx)`
// Conjunction of:
// curr[round_range(1)] = round(curr[round_range(0)])
// curr[round_range(2)] = round(curr[round_range(1)])
// curr[round_range(3)] = round(curr[round_range(2)])
// curr[round_range(4)] = round(curr[round_range(3)])
// next[round_range(0)] = round(curr[round_range(4)])
//
// which expands e.g., to
// curr[round_range(1)][0] =
//      mds[0][0] * sbox(curr[round_range(0)][0])
//    + mds[0][1] * sbox(curr[round_range(0)][1])
//    + mds[0][2] * sbox(curr[round_range(0)][2])
//    + rcm[round_range(1)][0]
// curr[round_range(1)][1] =
//      mds[1][0] * sbox(curr[round_range(0)][0])
//    + mds[1][1] * sbox(curr[round_range(0)][1])
//    + mds[1][2] * sbox(curr[round_range(0)][2])
//    + rcm[round_range(1)][1]
// ...
// The rth position in this array contains the alphas used for the equations that
// constrain the values of the (r+1)th state.
pub fn constraint<F: FftField + SquareRootField>(
        params: &ArithmeticSpongeParams<F>,
    ) -> E<F> {
    let mut res = vec![];
    let mut cache = Cache::new();

    let mut idx = 0;
    for e in ROUND_EQUATIONS.iter() {
        let &RoundEquation { source, target: (target_row, target_round) } = e;
        let sboxed : Vec<_> =
            round_to_cols(source).map(|i| {
                cache.cache(
                    E::cell(Column::Witness(i), Curr)
                    .pow(PlonkSpongeConstants15W::SPONGE_BOX))
            }).collect();

        res.extend(round_to_cols(target_round).enumerate().map(|(j, col)| {
            let rc = E::cell(Column::Coefficient(idx), Curr);

            idx += 1;

            E::cell(Column::Witness(col), target_row)
                -
            sboxed.iter()
            .zip(params.mds[j].iter())
            .fold(rc, |acc, (x, c)| acc + E::literal(*c) * x.clone())
        }));
    }
    E::cell(Column::Index(GateType::Poseidon), Curr) *
    E::combine_constraints(0, res)
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    pub fn psdn_scalars(
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> Vec<F> {
        let w_zeta = evals[0].w;
        let sboxed: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] = array_init(|round| {
            array_init(|i| {
                let col = round_to_cols(round);
                sbox::<F, PlonkSpongeConstants15W>(w_zeta[col][i])
            })
        });
        let alp: [[F; SPONGE_WIDTH]; ROUNDS_PER_ROW] =
            array_init(|round| array_init(|i| alpha[round * SPONGE_WIDTH + i]));

        let lhs = ROUND_EQUATIONS.iter().fold(F::zero(), |acc, eq| {
            let (target_row, target_round) = &eq.target;
            let cols = match target_row {
                Curr => &evals[0].w,
                Next => &evals[1].w,
            };
            cols[round_to_cols(*target_round)]
                .iter()
                .zip(alp[eq.source].iter())
                .map(|(p, a)| -*a * p)
                .fold(acc, |x, y| x + &y)
        });

        let mut rhs = F::zero();
        for eq in ROUND_EQUATIONS.iter() {
            let ss = sboxed[eq.source];
            let aa = alp[eq.source];
            for (i, p) in ss.iter().enumerate() {
                // Each of these contributes to the right hand side of SPONGE_WIDTH cell equations
                let coeff =
                    (0..SPONGE_WIDTH).fold(F::zero(), |acc, j| acc + aa[j] * params.mds[j][i]);
                rhs += coeff * p;
            }
        }

        let mut res = vec![lhs + rhs];

        // TODO(mimoo): how is that useful? we already have access to these
        for i in 0..COLUMNS {
            res.push(evals[0].poseidon_selector * alpha[i]);
        }
        res
    }

    /// poseidon linearization poly contribution computation f^7 + c(x) - f(wx)
    pub fn psdn_lnrz(
        &self,
        evals: &Vec<ProofEvaluations<F>>,
        params: &ArithmeticSpongeParams<F>,
        alpha: &[F],
    ) -> DensePolynomial<F> {
        let scalars = Self::psdn_scalars(evals, params, alpha);
        self.coefficientsm
            .iter()
            .zip(scalars[1..].iter())
            .map(|(r, a)| r.scale(*a))
            .fold(self.psm.scale(scalars[0]), |x, y| &x + &y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gate::CircuitGate,
        wires::{Wire, COLUMNS, PERMUTS},
    };

    use ark_ff::{UniformRand, Zero};
    use ark_poly::{EvaluationDomain, Polynomial};
    use array_init::array_init;
    use itertools::iterate;
    use mina_curves::pasta::fp::Fp;
    use oracle::{
        poseidon::SpongeConstants,
        rndoracle::{ArithmeticSponge, Sponge},
    };
    use rand::SeedableRng;

    /*
    #[test]
    fn test_poseidon_polynomial() {
        // create constraint system with a single poseidon gate
        let mut gates = vec![];

        // create poseidon gates
        let gates_row = 0;
        let first_wire = Wire::new(gates_row);
        let last_row = gates_row + POS_ROWS_PER_HASH;
        let last_wire = Wire::new(last_row);
        let params = oracle::pasta::fp::params();

        let (poseidon, gates_row) = CircuitGate::<Fp>::create_poseidon_gadget(
            gates_row,
            [first_wire, last_wire],
            &params.round_constants,
        );
        gates.extend(poseidon);

        // create constraint system
        let cs = ConstraintSystem::fp_for_testing(gates);

        // generate witness
        let n = cs.domain.d1.size();
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); n]);

        // fill witness
        let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstants15W>::new(params);
        let mut witness_row = iterate(0usize, |&i| i + 1);
        let mut abs_round = 0;
        assert!(!PlonkSpongeConstants15W::INITIAL_ARK); // for full_round

        for _ in 0..POS_ROWS_PER_HASH {
            let row = witness_row.next().unwrap();
            for round in 0..ROUNDS_PER_ROW {
                // the last round makes use of the next row
                let maybe_next_row = if round == ROUNDS_PER_ROW - 1 {
                    row + 1
                } else {
                    row
                };

                // apply the sponge and record the result in the witness
                sponge.full_round(abs_round);
                abs_round += 1;
                let cols_to_update = round_to_cols((round + 1) % ROUNDS_PER_ROW);
                for (w, s) in witness[cols_to_update].iter_mut().zip(sponge.state.iter()) {
                    w[maybe_next_row] = *s;
                }
            }
        }

        // make sure we're done filling the witness correctly
        assert_eq!(Some(gates_row), witness_row.next());
        assert_eq!(abs_round, 55);
        cs.verify(&witness).unwrap();

        // generate witness polynomials
        let witness_evals: [Evaluations<Fp, D<Fp>>; COLUMNS] =
            array_init(|col| Evaluations::from_vec_and_domain(witness[col].clone(), cs.domain.d1));
        let witness: [DensePolynomial<Fp>; COLUMNS] =
            array_init(|col| witness_evals[col].interpolate_by_ref());

        // make sure we've done that correctly
        //        let public = DensePolynomial::zero();
        //        assert!(cs.verify_poseidon(&witness, &public));

        // random zeta
        let rng = &mut rand::rngs::StdRng::from_seed([0; 32]);
        let zeta = Fp::rand(rng);

        // create alphas
        let mut alphas = vec![];
        // TODO(mimoo): replace with range::PSDN once it moves to circuit
        for _ in 0..15 {
            alphas.push(Fp::rand(rng));
        }

        // compute quotient by dividing with vanishing polynomial
        let lagrange = cs.evaluate(&witness, &DensePolynomial::zero());
        let (pos4, pos8) = cs.psdn_quot(&lagrange, &cs.fr_sponge_params, &alphas);
        let t_before_division = &pos4.interpolate() + &pos8.interpolate();
        let (t, rem) = t_before_division
            .divide_by_vanishing_poly(cs.domain.d1)
            .unwrap();
        assert!(rem.is_zero());
        let t_zeta = t.evaluate(&zeta);

        let evaluated = {
            let mut h = std::collections::HashSet::new();
            h.insert(Column::Index(GateType::Poseidon));
            h
        };
        let lin = constraint(&cs.fr_sponge_params).linearize(evaluated);

        // compute linearization f(z)
        let zeta_omega = zeta * &cs.domain.d1.group_gen;
        let w_zeta: [_; COLUMNS] = array_init(|col| witness[col].evaluate(&zeta));
        let w_zeta_omega: [_; COLUMNS] = array_init(|col| witness[col].evaluate(&zeta_omega));
        let evals = vec![
            ProofEvaluations {
                w: w_zeta,
                z: Fp::zero(),
                s: [Fp::zero(); PERMUTS - 1],
                lookup: None,
                generic_selector: Fp::zero(),
                poseidon_selector: cs.psm.evaluate(&zeta),
            },
            ProofEvaluations {
                w: w_zeta_omega,
                z: Fp::zero(),
                s: [Fp::zero(); PERMUTS - 1],
                lookup: None,
                generic_selector: Fp::zero(),
                poseidon_selector: cs.psm.evaluate(&zeta_omega),
            },
        ];
        let w_zeta: [Fp; COLUMNS] = array_init(|col| witness[col].evaluate(&zeta));
        let f = cs.psdn_lnrz(&evals, &cs.fr_sponge_params, &alphas);
        let f_zeta = f.evaluate(&zeta);

        // check that f(z) = t(z) * Z_H(z)
        let z_h_zeta = cs.domain.d1.evaluate_vanishing_polynomial(zeta);
        assert!(f_zeta == t_zeta * &z_h_zeta);
    }
*/
}
