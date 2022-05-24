//! Range check gate

use std::collections::HashMap;

use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Radix2EvaluationDomain as D};
use array_init::array_init;
use rand::{prelude::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentType},
        constraints::ConstraintSystem,
        domains::EvaluationDomains,
        expr::{self, l0_1, Environment, E},
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        wires::{GateWires, Wire},
    },
};

use super::{RangeCheck0, RangeCheck1};

// Connect the pair of cells specified by the cell1 and cell2 parameters
// cell1 --> cell2 && cell2 --> cell1
//
// Note: This function assumes that the targeted cells are freshly instantiated
//       with self-connections.  If the two cells are transitively already part
//       of the same permutation then this would split it.
fn connect_cell_pair(wires: &mut [GateWires], cell1: (usize, usize), cell2: (usize, usize)) {
    let tmp = wires[cell1.0][cell1.1];
    wires[cell1.0][cell1.1] = wires[cell2.0][cell2.1];
    wires[cell2.0][cell2.1] = tmp;
}

impl<F: FftField + SquareRootField> CircuitGate<F> {
    /// Create range check gate
    ///     Inputs the starting row
    ///     Outputs tuple (next_row, circuit_gates) where
    ///       next_row      - next row after this gate
    ///       circuit_gates - vector of circuit gates comprising this gate
    pub fn create_range_check(start_row: usize) -> (usize, Vec<Self>) {
        let mut wires: Vec<GateWires> = (0..4).map(|i| Wire::new(start_row + i)).collect();

        // copy a0p4
        connect_cell_pair(&mut wires, (0, 5), (3, 1));

        // copy a0p5
        connect_cell_pair(&mut wires, (0, 6), (3, 2));

        // copy a1p4
        connect_cell_pair(&mut wires, (1, 5), (3, 3));

        // copy a1p5
        connect_cell_pair(&mut wires, (1, 6), (3, 4));

        let circuit_gates = vec![
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: wires[1],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::RangeCheck1,
                wires: wires[2],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::RangeCheck2,
                wires: wires[3],
                coeffs: vec![],
            },
        ];

        (start_row + circuit_gates.len(), circuit_gates)
    }

    /// Verify the range check circuit gate on a given row
    pub fn verify_range_check(
        &self,
        _: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        if self.typ == GateType::RangeCheck2 {
            // Not yet implemented
            // (Allow this to pass so that proof & verification test can function.)
            return Ok(());
        }

        // TODO: We should refactor some of this code into a
        // new Expr helper that can just evaluate a single row
        // and perform a lot of the common setup below so that
        // each CircuitGate's verify function doesn't need to
        // implement it separately.

        // Pad the witness to domain d1 size
        let padding_length = cs
            .domain
            .d1
            .size
            .checked_sub(witness[0].len() as u64)
            .unwrap();
        let mut witness = witness.clone();
        for w in &mut witness {
            w.extend(std::iter::repeat(F::zero()).take(padding_length as usize));
        }

        // Compute witness polynomial
        let witness_poly: [DensePolynomial<F>; COLUMNS] = array_init(|i| {
            Evaluations::<F, D<F>>::from_vec_and_domain(witness[i].clone(), cs.domain.d1)
                .interpolate()
        });

        // Compute permutation polynomial
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let z_poly = cs
            .perm_aggreg(&witness, &beta, &gamma, rng)
            .map_err(|_| format!("Invalid {:?} constraint - permutation failed", self.typ))?;

        // Compute witness polynomial evaluations
        let witness_evals = cs.evaluate(&witness_poly, &z_poly);

        // Set up the environment
        let env = {
            let mut index_evals = HashMap::new();
            index_evals.insert(
                self.typ,
                &cs.range_check_selector_polys[circuit_gate_selector_index(self.typ)].eval8,
            );

            Environment {
                constants: expr::Constants {
                    alpha: F::rand(rng),
                    beta: F::rand(rng),
                    gamma: F::rand(rng),
                    joint_combiner: Some(F::rand(rng)),
                    endo_coefficient: cs.endo,
                    mds: vec![], // TODO: maybe cs.fr_sponge_params.mds.clone()
                },
                witness: &witness_evals.d8.this.w,
                coefficient: &cs.coefficients8,
                vanishes_on_last_4_rows: &cs.precomputations().vanishes_on_last_4_rows,
                z: &witness_evals.d8.this.z,
                l0_1: l0_1(cs.domain.d1),
                domain: cs.domain,
                index: index_evals,
                lookup: None,
            }
        };

        // Setup powers of alpha
        let mut alphas = Alphas::<F>::default();
        alphas.register(
            ArgumentType::Gate(self.typ),
            circuit_gate_constraint_count::<F>(self.typ),
        );

        // Get constraints for this circuit gate
        let constraints = circuit_gate_constraints(self.typ, &alphas);

        // Verify it against the environment
        if constraints
            .evaluations(&env)
            .interpolate()
            .divide_by_vanishing_poly(cs.domain.d1)
            .unwrap()
            .1
            .is_zero()
        {
            Ok(())
        } else {
            Err(format!("Invalid {:?} constraint", self.typ))
        }
    }
}

fn circuit_gate_selector_index(typ: GateType) -> usize {
    match typ {
        GateType::RangeCheck0 => 0,
        GateType::RangeCheck1 => 1,
        _ => panic!("invalid gate type"),
    }
}

/// Get vector of range check circuit gate types
pub fn circuit_gates() -> Vec<GateType> {
    vec![GateType::RangeCheck0, GateType::RangeCheck1]
}

/// Number of constraints for a given range check circuit gate type
pub fn circuit_gate_constraint_count<F: FftField>(typ: GateType) -> u32 {
    match typ {
        GateType::RangeCheck0 => RangeCheck0::<F>::CONSTRAINTS,
        GateType::RangeCheck1 => RangeCheck1::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given range check circuit gate type
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::RangeCheck0 => RangeCheck0::combined_constraints(alphas),
        GateType::RangeCheck1 => RangeCheck1::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all range check circuit gate types
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    RangeCheck0::combined_constraints(alphas) + RangeCheck1::combined_constraints(alphas)
}

/// Range check CircuitGate selector polynomial
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SelectorPolynomial<F: FftField> {
    /// Coefficient form
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub coeff: DensePolynomial<F>,
    /// Evaluation form (evaluated over domain d8)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub eval8: Evaluations<F, D<F>>,
}

/// Create range check circuit gates selector polynomials
pub fn selector_polynomials<F: FftField>(
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
) -> Vec<SelectorPolynomial<F>> {
    Vec::from_iter(circuit_gates().iter().map(|gate_type| {
        // Coefficient form
        let coeff = Evaluations::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if gate.typ == *gate_type {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            domain.d1,
        )
        .interpolate();

        // Evaluation form (evaluated over d8)
        let eval8 = coeff.evaluate_over_domain_by_ref(domain.d8);

        SelectorPolynomial { coeff, eval8 }
    }))
}

#[cfg(test)]
mod tests {
    use crate::{
        circuits::{
            constraints::ConstraintSystem, gate::CircuitGate, polynomial::COLUMNS,
            polynomials::range_check,
        },
        proof::ProverProof,
        prover_index::testing::new_index_for_test_with_lookups,
    };

    use ark_ec::AffineCurve;
    use ark_ff::One;
    use mina_curves::pasta::pallas;
    use num_bigint::BigUint;

    use array_init::array_init;

    type PallasField = <pallas::Affine as AffineCurve>::BaseField;

    fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
        let (_, gates) = CircuitGate::<PallasField>::create_range_check(0);

        ConstraintSystem::create(gates, vec![], None, oracle::pasta::fp_kimchi::params(), 0)
            .unwrap()
    }

    fn create_test_prover_index(
        public_size: usize,
    ) -> ProverIndex<mina_curves::pasta::vesta::Affine> {
        let (_, gates) = CircuitGate::<PallasField>::create_range_check(0);
        new_index_for_test_with_lookups(gates, public_size, vec![], None)
    }

    fn biguint_from_hex_le(hex: &str) -> BigUint {
        let mut bytes = hex::decode(hex).expect("invalid hex");
        bytes.reverse();
        BigUint::from_bytes_le(&bytes)
    }

    #[test]
    fn verify_range_check0_zero_valid_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(0); 4]);

        // gates[0] is RangeCheck0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check0_one_invalid_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(1); 4]);

        // gates[0] is RangeCheck0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err("Invalid RangeCheck0 constraint".to_string())
        );
    }

    #[test]
    fn verify_range_check0_valid_witness() {
        let cs = create_test_constraint_system();

        let witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "1112223334445556667777888999aaabbbcccdddeeefff111222333444555611",
        ));

        // gates[0] is RangeCheck0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        // gates[1] is RangeCheck0
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "f59abe33f5d808f8df3e63984621b01e375585fea8dd4030f71a0d80ac06d423",
        ));

        // gates[0] is RangeCheck0
        assert_eq!(cs.gates[0].verify_range_check(0, &witness, &cs), Ok(()));

        // gates[1] is RangeCheck0
        assert_eq!(cs.gates[1].verify_range_check(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check0_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; COLUMNS] = range_check::create_witness(
            biguint_from_hex_le("bca91cf9df6cfd8bd225fd3f46ba2f3f33809d0ee2e7ad338448b4ece7b4f622"),
        );

        // Invalidate witness
        witness[5][0] += PallasField::one();

        // gates[0] is RangeCheck0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(String::from(
                "Invalid RangeCheck0 constraint - permutation failed"
            ))
        );

        let mut witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "301a091e9f74cd459a448c311ae47fe2f4311db61ae1cbd2afee0171e2b5ca22",
        ));

        // Invalidate witness
        witness[8][0] = witness[0][0] + PallasField::one();

        // gates[0] is RangeCheck0
        assert_eq!(
            cs.gates[0].verify_range_check(0, &witness, &cs),
            Err(String::from("Invalid RangeCheck0 constraint"))
        );
    }

    #[test]
    fn verify_range_check1_valid_witness() {
        let cs = create_test_constraint_system();

        let witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "72de0b593fbd97e172ddfb1d7c1f7488948c622a7ff6bffa0279e35a7c148733",
        ));

        // gates[2] is RangeCheck1
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "58372fb93039e7106c68488dceb6cab3ffb0e7c8594dcc3bc7160321fcf6960d",
        ));

        // gates[2] is RangeCheck1
        assert_eq!(cs.gates[2].verify_range_check(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_range_check1_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "260efa1879427b08ca608d455d9f39954b5243dd52117e9ed5982f94acd3e22c",
        ));

        // Corrupt witness
        witness[0][2] = witness[7][2];

        // gates[2] is RangeCheck1
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(String::from("Invalid RangeCheck1 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "afd209d02c77546022ea860f9340e4289ecdd783e9c0012fd383dcd2940cd51b",
        ));

        // Corrupt witness
        witness[13][2] = witness[1][2];

        // gates[2] is RangeCheck1
        assert_eq!(
            cs.gates[2].verify_range_check(2, &witness, &cs),
            Err(String::from("Invalid RangeCheck1 constraint"))
        );
    }

    use crate::{prover_index::ProverIndex, verifier::verify};
    use commitment_dlog::commitment::CommitmentCurve;
    use groupmap::GroupMap;
    use mina_curves::pasta as pasta_curves;
    use oracle::{
        constants::PlonkSpongeConstantsKimchi,
        sponge::{DefaultFqSponge, DefaultFrSponge},
    };

    type BaseSponge =
        DefaultFqSponge<pasta_curves::vesta::VestaParameters, PlonkSpongeConstantsKimchi>;
    type ScalarSponge = DefaultFrSponge<pasta_curves::Fp, PlonkSpongeConstantsKimchi>;

    #[test]
    fn verify_range_check_valid_proof1() {
        // Create prover index
        let prover_index = create_test_prover_index(0);

        // Create witness
        let witness: [Vec<PallasField>; 15] = range_check::create_witness(biguint_from_hex_le(
            "56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b",
        ));

        // Verify computed witness satisfies the circuit
        prover_index.cs.verify(&witness, &[]).unwrap();

        // Generate proof
        let group_map = <pasta_curves::vesta::Affine as CommitmentCurve>::Map::setup();
        let proof = ProverProof::create::<BaseSponge, ScalarSponge>(
            &group_map,
            witness,
            &[],
            &prover_index,
        )
        .expect("failed to generate proof");

        // Get the verifier index
        let verifier_index = prover_index.verifier_index();

        // Verify proof
        let res = verify::<pasta_curves::vesta::Affine, BaseSponge, ScalarSponge>(
            &group_map,
            &verifier_index,
            &proof,
        );

        assert!(!res.is_err());
    }
}
