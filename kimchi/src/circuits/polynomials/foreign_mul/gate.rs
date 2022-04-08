use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial as DP, Evaluations as EV, Radix2EvaluationDomain as D};
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
        expr::{self, Column, E},
        gate::{CircuitGate, GateType},
        polynomial::COLUMNS,
        wires::GateWires,
    },
    proof::ProofEvaluations,
};

use super::{ForeignMul0, ForeignMul1, ForeignMul2};

impl<F: FftField> CircuitGate<F> {
    /// Create foreign multiplication gate
    pub fn create_foreign_mul(wires: &[GateWires; 8]) -> Vec<Self> {
        vec![
            /* Input: a */
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[0],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[1],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul1,
                wires: wires[2],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul2,
                wires: wires[3],
                coeffs: vec![],
            },
            /* Input: b */
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[4],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul0,
                wires: wires[5],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul1,
                wires: wires[6],
                coeffs: vec![],
            },
            CircuitGate {
                typ: GateType::ForeignMul2,
                wires: wires[7],
                coeffs: vec![],
            },
        ]
    }

    // Verify the foreign field multiplication circuit gate on a given row
    pub fn verify_foreign_mul(
        &self,
        row: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> Result<(), String> {
        // Witness row shorthands
        let curr: [F; COLUMNS] = array_init(|i| witness[i][row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][row + 1]);

        // Columns types that need to be evaluated for this gate to work
        let evaluated_cols = {
            let mut h = std::collections::HashSet::new();
            // Witness columns
            for i in 0..COLUMNS {
                h.insert(Column::Witness(i));
            }
            // Index column for each foreign field multiplication circuit gate
            h.extend(
                circuit_gates()
                    .iter()
                    .map(|gate_type| Column::Index(*gate_type)),
            );
            h
        };

        // Setup powers of alpha
        let mut alphas = Alphas::<F>::default();
        alphas.register(
            ArgumentType::Gate(self.typ),
            circuit_gate_constraint_count::<F>(self.typ),
        );

        // Get constraints for this circuit gate
        let constraints = circuit_gate_constraints(self.typ, &alphas);

        // Linearize
        let linearized = constraints.linearize(evaluated_cols).unwrap();

        // Setup proof evaluations
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let mut eval = |witness| ProofEvaluations {
            w: witness,
            z: F::rand(rng),
            s: array_init(|_| F::rand(rng)),
            generic_selector: F::zero(),
            poseidon_selector: F::zero(),
            lookup: None,
            foreign_mul_selector: match self.typ {
                // Force this circuit gate on
                GateType::ForeignMul0 => vec![F::one(), F::zero(), F::zero()],
                GateType::ForeignMul1 => vec![F::zero(), F::one(), F::zero()],
                GateType::ForeignMul2 => vec![F::zero(), F::zero(), F::one()],
                _ => panic!("Invalid gate type {:?}", self.typ),
            },
        };
        let evals = vec![eval(curr), eval(next)];

        // Setup circuit constants
        let constants = expr::Constants {
            alpha: F::rand(rng),
            beta: F::rand(rng),
            gamma: F::rand(rng),
            joint_combiner: F::rand(rng),
            endo_coefficient: cs.endo,
            mds: vec![],
            foreign_modulus: cs.foreign_modulus.clone(),
        };

        let pt = F::rand(rng);

        // Evaluate constraints
        match linearized
            .constant_term
            .evaluate_(cs.domain.d1, pt, &evals, &constants)
        {
            Ok(x) => {
                if x == F::zero() {
                    Ok(())
                } else {
                    Err(format!("Invalid {:?} constraint", self.typ))
                }
            }
            Err(_) => Err(format!("Failed to evaluate {:?} constraint", self.typ)),
        }
    }
}

/// Get vector of foreign field multiplication circuit gate types
pub fn circuit_gates() -> Vec<GateType> {
    vec![
        GateType::ForeignMul0,
        GateType::ForeignMul1,
        GateType::ForeignMul2,
    ]
}

/// Number of constraints for a given foreign field multiplication circuit gate type
pub fn circuit_gate_constraint_count<F: FftField>(typ: GateType) -> u32 {
    match typ {
        GateType::ForeignMul0 => ForeignMul0::<F>::CONSTRAINTS,
        GateType::ForeignMul1 => ForeignMul1::<F>::CONSTRAINTS,
        GateType::ForeignMul2 => ForeignMul2::<F>::CONSTRAINTS,
        _ => panic!("invalid gate type"),
    }
}

/// Get combined constraints for a given foreign field multiplication circuit gate type
pub fn circuit_gate_constraints<F: FftField>(typ: GateType, alphas: &Alphas<F>) -> E<F> {
    match typ {
        GateType::ForeignMul0 => ForeignMul0::combined_constraints(alphas),
        GateType::ForeignMul1 => ForeignMul1::combined_constraints(alphas),
        GateType::ForeignMul2 => ForeignMul2::combined_constraints(alphas),
        _ => panic!("invalid gate type"),
    }
}

/// Get the combined constraints for all foreign field multiplication circuit gate types
pub fn combined_constraints<F: FftField>(alphas: &Alphas<F>) -> E<F> {
    ForeignMul0::combined_constraints(alphas)
        + ForeignMul1::combined_constraints(alphas)
        + ForeignMul2::combined_constraints(alphas)
}

/// Foreign field multiplication CircuitGate selector polynomials
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SelectorPolynomial<F: FftField> {
    /// Coefficient form
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub coeff: DP<F>,
    /// Evaluation form (evaluated over domain d8)
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub eval8: EV<F, D<F>>,
}

/// Create foreign field multiplication circuit gates selector polynomials
pub fn selector_polynomials<F: FftField>(
    gates: &[CircuitGate<F>],
    domain: &EvaluationDomains<F>,
) -> Vec<SelectorPolynomial<F>> {
    Vec::from_iter(circuit_gates().iter().map(|gate_type| {
        // Coefficient form
        let coeff = EV::<F, D<F>>::from_vec_and_domain(
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
            polynomials::foreign_mul, wires::Wire,
        },
        proof::ProverProof,
        prover_index::testing::new_index_for_test,
    };

    use ark_ec::AffineCurve;
    use ark_ff::One;
    use mina_curves::pasta::{pallas, vesta};
    use num_bigint::BigUint;

    use array_init::array_init;

    type PallasField = <pallas::Affine as AffineCurve>::BaseField;
    type VestaField = <vesta::Affine as AffineCurve>::BaseField;

    fn create_test_constraint_system() -> ConstraintSystem<PallasField> {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);

        ConstraintSystem::create(
            gates,
            vec![],
            oracle::pasta::fp_kimchi::params(),
            o1_utils::packed_modulus::<PallasField>(o1_utils::get_modulus::<VestaField>()),
            0,
        )
        .unwrap()
    }

    fn create_test_prover_index(
        foreign_modulus: BigUint,
        public_size: usize,
    ) -> ProverIndex<mina_curves::pasta::vesta::Affine> {
        let wires = array_init(|i| Wire::new(i));
        let gates = CircuitGate::<PallasField>::create_foreign_mul(&wires);
        new_index_for_test(
            gates,
            o1_utils::packed_modulus::<PallasField>(foreign_modulus),
            public_size,
        )
    }

    fn biguint_from_hex_le(hex: &str) -> BigUint {
        let mut bytes = hex::decode(hex).expect("invalid hex");
        bytes.reverse();
        BigUint::from_bytes_le(&bytes)
    }

    #[test]
    fn verify_foreign_mul0_zero_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(0); 2]);

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul0_one_witness() {
        let cs = create_test_constraint_system();
        let witness: [Vec<PallasField>; COLUMNS] = array_init(|_| vec![PallasField::from(1); 2]);

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err("Invalid ForeignMul0 constraint".to_string())
        );
    }

    #[test]
    fn verify_foreign_mul0_valid_witness() {
        let cs = create_test_constraint_system();

        let witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("1112223334445556667777888999aaabbbcccdddeeefff111222333444555611"),
            biguint_from_hex_le("1112223334445556667777888999aaabbbcccdddeeefff111222333444555611"),
        );

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));

        // gates[1] is ForeignMul0
        assert_eq!(cs.gates[1].verify_foreign_mul(1, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("f59abe33f5d808f8df3e63984621b01e375585fea8dd4030f71a0d80ac06d423"),
            biguint_from_hex_le("f59abe33f5d808f8df3e63984621b01e375585fea8dd4030f71a0d80ac06d423"),
        );

        // gates[0] is ForeignMul0
        assert_eq!(cs.gates[0].verify_foreign_mul(0, &witness, &cs), Ok(()));

        // gates[1] is ForeignMul0
        assert_eq!(cs.gates[1].verify_foreign_mul(1, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul0_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("bca91cf9df6cfd8bd225fd3f46ba2f3f33809d0ee2e7ad338448b4ece7b4f622"),
            biguint_from_hex_le("bca91cf9df6cfd8bd225fd3f46ba2f3f33809d0ee2e7ad338448b4ece7b4f622"),
        );

        // Invalidate witness
        witness[5][0] += PallasField::one();

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err(String::from("Invalid ForeignMul0 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("301a091e9f74cd459a448c311ae47fe2f4311db61ae1cbd2afee0171e2b5ca22"),
            biguint_from_hex_le("301a091e9f74cd459a448c311ae47fe2f4311db61ae1cbd2afee0171e2b5ca22"),
        );

        // Invalidate witness
        witness[8][0] = witness[0][0] + PallasField::one();

        // gates[0] is ForeignMul0
        assert_eq!(
            cs.gates[0].verify_foreign_mul(0, &witness, &cs),
            Err(String::from("Invalid ForeignMul0 constraint"))
        );
    }

    #[test]
    fn verify_foreign_mul1_valid_witness() {
        let cs = create_test_constraint_system();

        let witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("72de0b593fbd97e172ddfb1d7c1f7488948c622a7ff6bffa0279e35a7c148733"),
            biguint_from_hex_le("72de0b593fbd97e172ddfb1d7c1f7488948c622a7ff6bffa0279e35a7c148733"),
        );

        // gates[2] is ForeignMul1
        assert_eq!(cs.gates[2].verify_foreign_mul(2, &witness, &cs), Ok(()));

        let witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("58372fb93039e7106c68488dceb6cab3ffb0e7c8594dcc3bc7160321fcf6960d"),
            biguint_from_hex_le("58372fb93039e7106c68488dceb6cab3ffb0e7c8594dcc3bc7160321fcf6960d"),
        );

        // gates[2] is ForeignMul1
        assert_eq!(cs.gates[2].verify_foreign_mul(2, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul1_invalid_witness() {
        let cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("260efa1879427b08ca608d455d9f39954b5243dd52117e9ed5982f94acd3e22c"),
            biguint_from_hex_le("260efa1879427b08ca608d455d9f39954b5243dd52117e9ed5982f94acd3e22c"),
        );

        // Corrupt witness
        witness[0][2] = witness[7][2];

        // gates[2] is ForeignMul1
        assert_eq!(
            cs.gates[2].verify_foreign_mul(2, &witness, &cs),
            Err(String::from("Invalid ForeignMul1 constraint"))
        );

        let mut witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("afd209d02c77546022ea860f9340e4289ecdd783e9c0012fd383dcd2940cd51b"),
            biguint_from_hex_le("afd209d02c77546022ea860f9340e4289ecdd783e9c0012fd383dcd2940cd51b"),
        );

        // Corrupt witness
        witness[13][2] = witness[1][2];

        // gates[2] is ForeignMul1
        assert_eq!(
            cs.gates[2].verify_foreign_mul(2, &witness, &cs),
            Err(String::from("Invalid ForeignMul1 constraint"))
        );
    }

    #[test]
    fn verify_foreign_mul2_valid_witness() {
        let _cs = create_test_constraint_system();

        let _witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("1aed1a6bc2ca84ee6edaedea4eb9b623392d24f64dfb0a8134ff16289bfc3c1f"),
            biguint_from_hex_le("1aed1a6bc2ca84ee6edaedea4eb9b623392d24f64dfb0a8134ff16289bfc3c1f"),
        );

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));

        let _witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("fd944d6dad12b5398bd2901b92439c6af31eca1766a1915bcd611df90830b508"),
            biguint_from_hex_le("fd944d6dad12b5398bd2901b92439c6af31eca1766a1915bcd611df90830b508"),
        );

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));
    }

    #[test]
    fn verify_foreign_mul2_invalid_witness() {
        let _cs = create_test_constraint_system();

        let mut witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
        );

        // Corrupt witness
        witness[12][2] = witness[2][2];

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));

        let mut witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
        );

        // Corrupt witness
        witness[6][2] = witness[3][2];

        // gates[3] is ForeignMul2 (cannot validate until plookup is implemented)
        // assert_eq!(cs.gates[3].verify_foreign_mul(3, &witness, &cs), Ok(()));
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
    fn verify_foreign_mul_proof1() {
        // Create prover index
        let prover_index = create_test_prover_index(o1_utils::get_modulus::<VestaField>(), 0);

        // Create witness
        let witness: [Vec<PallasField>; 15] = foreign_mul::create_witness(
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
            biguint_from_hex_le("56acede83576c45ec8c11a85ac97e2393a9f88308b4b42d1b1506f2faaafc02b"),
        );

        // Verify computed witness satisfies the circuit
        prover_index.cs.verify(&witness, &[]).unwrap();

        // Generate proof
        let group_map = <pasta_curves::vesta::Affine as CommitmentCurve>::Map::setup();
        let proof =
            ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &prover_index)
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
