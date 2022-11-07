//~ Rotation of a 64-bit word by a known offset

use crate::{
    alphas::Alphas,
    circuits::{
        argument::{Argument, ArgumentEnv, ArgumentType},
        constraints::ConstraintSystem,
        expr::{
            self,
            constraints::{crumb, ExprOps},
            l0_1, Environment, LookupEnvironment,
        },
        gate::{CircuitGate, CircuitGateError, CircuitGateResult, Connect, GateType},
        lookup::{
            self,
            lookups::{LookupInfo, LookupsUsed},
        },
        polynomial::COLUMNS,
        polynomials::{generic::GenericGateSpec, range_check::witness::range_check_0_row},
        wires::Wire,
        witness::{self, Variables, WitnessCell},
        witness::{SumCopyBitsCell, VariableCell},
    },
    curve::KimchiCurve,
    variable_map,
};
use ark_ff::{PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Radix2EvaluationDomain as D,
};
use rand::{rngs::StdRng, SeedableRng};
use std::marker::PhantomData;
use std::{array, collections::HashMap};

impl<F: PrimeField> CircuitGate<F> {
    /// Creates a Rot64 gadget to rotate a word
    /// It will need:
    /// - 1 Generic gate to constrain to zero some limbs
    ///
    /// It has:
    /// - 1 Rot64 gate to rotate the word
    /// - 1 RangeCheck0 to constrain the size of some parameters
    pub fn create_rot64(new_row: usize, rot: u32) -> Vec<Self> {
        vec![
            CircuitGate {
                typ: GateType::Rot64,
                wires: Wire::new(new_row),
                coeffs: vec![F::from(2u32).pow(&[rot as u64])],
            },
            CircuitGate {
                typ: GateType::RangeCheck0,
                wires: Wire::new(new_row + 1),
                coeffs: vec![],
            },
        ]
    }

    /// Create one rotation
    /// TODO: right now it only creates a Generic gate followed by the Rot64 gates
    pub fn create_rot(new_row: usize, rot: u32) -> (usize, Vec<Self>) {
        // Initial Generic gate to constrain the output to be zero
        let zero_row = new_row;
        let mut gates = vec![CircuitGate::<F>::create_generic_gadget(
            Wire::new(new_row),
            GenericGateSpec::Pub,
            None,
        )];

        let rot_row = zero_row + 1;
        let mut rot64_gates = Self::create_rot64(rot_row, rot);
        // Append them to the full gates vector
        gates.append(&mut rot64_gates);
        // Check that 2 most significant limbs of shifted are zero
        gates.connect_64bit(zero_row, rot_row + 1);

        (new_row + gates.len(), gates)
    }

    /// Verifies the rotation gate
    pub fn verify_rot<G: KimchiCurve<ScalarField = F>>(
        &self,
        _: usize,
        witness: &[Vec<F>; COLUMNS],
        cs: &ConstraintSystem<F>,
    ) -> CircuitGateResult<()> {
        if ![GateType::Rot64].contains(&self.typ) {
            return Err(CircuitGateError::InvalidCircuitGateType(self.typ));
        }

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
        let witness_poly: [DensePolynomial<F>; COLUMNS] = array::from_fn(|i| {
            Evaluations::<F, D<F>>::from_vec_and_domain(witness[i].clone(), cs.domain.d1)
                .interpolate()
        });

        // Compute permutation polynomial
        let rng = &mut StdRng::from_seed([0u8; 32]);
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let z_poly = cs
            .perm_aggreg(&witness, &beta, &gamma, rng)
            .map_err(|_| CircuitGateError::InvalidCopyConstraint(self.typ))?;

        // Compute witness polynomial evaluations
        let witness_evals = cs.evaluate(&witness_poly, &z_poly);

        let mut index_evals = HashMap::new();
        index_evals.insert(self.typ, &cs.rot_selector_poly.as_ref().unwrap().eval8);

        // Set up lookup environment
        let lcs = cs
            .lookup_constraint_system
            .as_ref()
            .ok_or(CircuitGateError::MissingLookupConstraintSystem(self.typ))?;

        let lookup_env_data = set_up_lookup_env_data(
            self.typ,
            cs,
            &witness,
            &beta,
            &gamma,
            &lcs.configuration.lookup_info,
        )?;
        let lookup_env = Some(LookupEnvironment {
            aggreg: &lookup_env_data.aggreg8,
            sorted: &lookup_env_data.sorted8,
            selectors: &lcs.lookup_selectors,
            table: &lookup_env_data.joint_lookup_table_d8,
            runtime_selector: None,
            runtime_table: None,
        });

        // Set up the environment
        let env = {
            Environment {
                constants: expr::Constants {
                    alpha: F::rand(rng),
                    beta: F::rand(rng),
                    gamma: F::rand(rng),
                    joint_combiner: Some(F::rand(rng)),
                    endo_coefficient: cs.endo,
                    mds: &G::sponge_params().mds,
                    foreign_field_modulus: None,
                },
                witness: &witness_evals.d8.this.w,
                coefficient: &cs.coefficients8,
                vanishes_on_last_4_rows: &cs.precomputations().vanishes_on_last_4_rows,
                z: &witness_evals.d8.this.z,
                l0_1: l0_1(cs.domain.d1),
                domain: cs.domain,
                index: index_evals,
                lookup: lookup_env,
            }
        };

        // Setup powers of alpha
        let mut alphas = Alphas::<F>::default();
        alphas.register(ArgumentType::Gate(self.typ), Rot64::<F>::CONSTRAINTS);

        // Get constraints for this circuit gate
        let constraints = Rot64::combined_constraints(&alphas);

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
            Err(CircuitGateError::InvalidConstraint(self.typ))
        }
    }
}

// Data required by the lookup environment
struct LookupEnvironmentData<F: PrimeField> {
    // Aggregation evaluations
    aggreg8: Evaluations<F, D<F>>,
    // Sorted evaluations
    sorted8: Vec<Evaluations<F, D<F>>>,
    // Combined lookup table
    joint_lookup_table_d8: Evaluations<F, D<F>>,
}

// Helper to create the lookup environment data by setting up the joint- and table-id- combiners,
// computing the dummy lookup value, creating the combined lookup table, computing the sorted plookup
// evaluations and the plookup aggregation evaluations.
// Note: This function assumes the cs contains a lookup constraint system.
fn set_up_lookup_env_data<F: PrimeField>(
    gate_type: GateType,
    cs: &ConstraintSystem<F>,
    witness: &[Vec<F>; COLUMNS],
    beta: &F,
    gamma: &F,
    lookup_info: &LookupInfo,
) -> CircuitGateResult<LookupEnvironmentData<F>> {
    let lcs = cs
        .lookup_constraint_system
        .as_ref()
        .ok_or(CircuitGateError::MissingLookupConstraintSystem(gate_type))?;

    let rng = &mut StdRng::from_seed([1u8; 32]);

    // Set up joint-combiner and table-id-combiner
    let joint_lookup_used = matches!(lcs.configuration.lookup_used, LookupsUsed::Joint);
    let joint_combiner = if joint_lookup_used {
        F::rand(rng)
    } else {
        F::zero()
    };
    let table_id_combiner: F = if lcs.table_ids8.as_ref().is_some() {
        joint_combiner.pow([u64::from(lcs.configuration.lookup_info.max_joint_size)])
    } else {
        // TODO: just set this to None in case multiple tables are not used
        F::zero()
    };

    // Compute the dummy lookup value as the combination of the last entry of the XOR table (so `(0, 0, 0)`).
    // Warning: This assumes that we always use the XOR table when using lookups.
    let dummy_lookup_value = lcs
        .configuration
        .dummy_lookup
        .evaluate(&joint_combiner, &table_id_combiner);

    // Compute the lookup table values as the combination of the lookup table entries.
    let joint_lookup_table_d8 = {
        let mut evals = Vec::with_capacity(cs.domain.d1.size());

        for idx in 0..(cs.domain.d1.size() * 8) {
            let table_id = match lcs.table_ids8.as_ref() {
                Some(table_ids8) => table_ids8.evals[idx],
                None =>
                // If there is no `table_ids8` in the constraint system,
                // every table ID is identically 0.
                {
                    F::zero()
                }
            };

            let combined_entry = {
                let table_row = lcs.lookup_table8.iter().map(|e| &e.evals[idx]);

                lookup::tables::combine_table_entry(
                    &joint_combiner,
                    &table_id_combiner,
                    table_row,
                    &table_id,
                )
            };
            evals.push(combined_entry);
        }

        Evaluations::from_vec_and_domain(evals, cs.domain.d8)
    };

    // Compute the sorted plookup evaluations
    // TODO: Once we switch to committing using lagrange commitments, `witness` will be consumed when we interpolate,
    //       so interpolation will have to moved below this.
    let sorted: Vec<_> = lookup::constraints::sorted(
        dummy_lookup_value,
        &joint_lookup_table_d8,
        cs.domain.d1,
        &cs.gates,
        witness,
        joint_combiner,
        table_id_combiner,
        lookup_info,
    )
    .map_err(|_| CircuitGateError::InvalidLookupConstraintSorted(gate_type))?;

    // Randomize the last `EVALS` rows in each of the sorted polynomials in order to add zero-knowledge to the protocol.
    let sorted: Vec<_> = sorted
        .into_iter()
        .map(|chunk| lookup::constraints::zk_patch(chunk, cs.domain.d1, rng))
        .collect();

    let sorted_coeffs: Vec<_> = sorted.iter().map(|e| e.clone().interpolate()).collect();
    let sorted8 = sorted_coeffs
        .iter()
        .map(|v| v.evaluate_over_domain_by_ref(cs.domain.d8))
        .collect::<Vec<_>>();

    // Compute the plookup aggregation evaluations
    let aggreg = lookup::constraints::aggregation::<_, F>(
        dummy_lookup_value,
        &joint_lookup_table_d8,
        cs.domain.d1,
        &cs.gates,
        witness,
        &joint_combiner,
        &table_id_combiner,
        *beta,
        *gamma,
        &sorted,
        rng,
        lookup_info,
    )
    .map_err(|_| CircuitGateError::InvalidLookupConstraintAggregation(gate_type))?;

    // Precompute different forms of the aggregation polynomial for later
    let aggreg_coeffs = aggreg.interpolate();
    // TODO: There's probably a clever way to expand the domain without interpolating
    let aggreg8 = aggreg_coeffs.evaluate_over_domain_by_ref(cs.domain.d8);

    Ok(LookupEnvironmentData {
        aggreg8,
        sorted8,
        joint_lookup_table_d8,
    })
}

//~ ##### `Rot64` - Constraints for known-length rotation of 64-bit words
//~
//~ * This circuit gate is used to constrain that a 64-bit word is rotated by r<64 bits to the "left".
//~ * The rotation is performed towards the most significant side (thus, the new LSB is fed with the old MSB).
//~ * This gate operates on the `Curr` and `Next` rows.
//~
//~ The idea is to split the rotation operation into two parts:
//~ * Shift to the left
//~ * Add the excess bits to the right
//~
//~ We represent shifting with multiplication modulo 2^{64}. That is, for each word to be rotated, we provide in
//~ the witness a quotient and a remainder, similarly to `ForeignFieldMul` such that the following operation holds:
//~
//~ $$word \cdot 2^{rot} = quotient \cdot 2^{64} + remainder$$
//~
//~ Then, the remainder corresponds to the shifted word, and the quotient corresponds to the excess bits.
//~ Thus, in order to obtain the rotated word, we need to add the quotient and the remainder as follows:
//~
//~ $$rotated = shifted + excess$$
//~
//~ The input word is known to be of length 64 bits. All we need for soundness is check that the shifted and
//~ excess parts of the word have the correct size as well. That means, we need to range check that:
//~ $$
//~ \begin{aligned}
//~ excess &< 2^{rot}\\
//~ shifted &< 2^{64}
//~ \end{aligned}
//~ $$
//~ The latter can be obtained with a `RangeCheck0` gate setting the two most significant limbs to zero.
//~ The former is equivalent to the following check:
//~ $$excess - 2^{rot} + 2^{64} < 2^{64}$$
//~ which is doable with the constraints in a `RangeCheck0` gate. Since our current row within the `Rot64` gate
//~ is almost empty, we can use it to perform the range check within the same gate. Then, using the following layout
//~ and assuming that the gate has a coefficient storing the value $2^{rot}$, which is publicly known
//~
//~ | Gate   | `Rot64`             | `RangeCheck0`    |
//~ | ------ | ------------------- | ---------------- |
//~ | Column | `Curr`              | `Next`           |
//~ | ------ | ------------------- | ---------------- |
//~ |      0 | copy `word`         |`shifted`         |
//~ |      1 | copy `rotated`      | 0                |
//~ |      2 |      `excess`       | 0                |
//~ |      3 |      `bound_limb0`  | `shifted_limb0`  |
//~ |      4 |      `bound_limb1`  | `shifted_limb1`  |
//~ |      5 |      `bound_limb2`  | `shifted_limb2`  |
//~ |      6 |      `bound_limb3`  | `shifted_limb3`  |
//~ |      7 |      `bound_crumb0` | `shifted_crumb0` |
//~ |      8 |      `bound_crumb1` | `shifted_crumb1` |
//~ |      9 |      `bound_crumb2` | `shifted_crumb2` |
//~ |     10 |      `bound_crumb3` | `shifted_crumb3` |
//~ |     11 |      `bound_crumb4` | `shifted_crumb4` |
//~ |     12 |      `bound_crumb5` | `shifted_crumb5` |
//~ |     13 |      `bound_crumb6` | `shifted_crumb6` |
//~ |     14 |      `bound_crumb7` | `shifted_crumb7` |
//~
//~ In Keccak, rotations are performed over a 5x5 matrix state of w-bit words each cell. The values used
//~ to perform the rotation are fixed, public, and known in advance, according to the following table:
//~
//~ | y \ x |   0 |   1 |   2 |   3 |   4 |
//~ | ----- | --- | --- | --- | --- | --- |
//~ | 0     |   0 |   1 | 190 |  28 |  91 |
//~ | 1     |  36 | 300 |   6 |  55 | 276 |
//~ | 2     |   3 |  10 | 171 | 153 | 231 |
//~ | 3     | 105 |  45 |  15 |  21 | 136 |
//~ | 4     | 210 |  66 | 253 | 120 |  78 |
//~
//~ But since we are always using 64-bit words, we can have an equivalent table with these values modulo 64
//~ to avoid needing multiple passes of the rotation gate (a single step would cause overflows):
//~
//~ | y \ x |   0 |   1 |   2 |   3 |   4 |
//~ | ----- | --- | --- | --- | --- | --- |
//~ | 0     |   0 |   1 |  62 |  28 |  27 |
//~ | 1     |  36 |  44 |   6 |  55 |  20 |
//~ | 2     |   3 |  10 |  43 |  25 |  39 |
//~ | 3     |  41 |  45 |  15 |  21 |   8 |
//~ | 4     |  18 |   2 |  61 |  56 |  14 |
//~
//~ Since there is one value of the coordinates (x, y) where the rotation is 0 bits, we can skip that step in the
//~ gadget. This will save us one gate, and thus the whole 25-1=24 rotations will be performed in just 48 rows.
//~
#[derive(Default)]
pub struct Rot64<F>(PhantomData<F>);

impl<F> Argument<F> for Rot64<F>
where
    F: PrimeField,
{
    const ARGUMENT_TYPE: ArgumentType = ArgumentType::Gate(GateType::Rot64);
    const CONSTRAINTS: u32 = 11;

    // Constraints for rotation of three 64-bit words by any three number of bits modulo 64
    // (stored in coefficient as a power-of-two form)
    //   * Operates on Curr row
    //   * Shifts the words by `rot` bits and then adds the excess to obtain the rotated word.
    fn constraint_checks<T: ExprOps<F>>(env: &ArgumentEnv<F, T>) -> Vec<T> {
        // Check that the last 8 columns are 2-bit crumbs
        let mut constraints = (7..COLUMNS)
            .map(|i| crumb(&env.witness_curr(i)))
            .collect::<Vec<T>>();

        // TODO:
        // If we ever want to make this gate more generic, the power of two for the length
        // could be a coefficient of the gate instead of a fixed value in the constraints.
        let two_to_64 = T::from(2u64).pow(64);

        let word = env.witness_curr(0);
        let rotated = env.witness_curr(1);
        let excess = env.witness_curr(2);
        let shifted = env.witness_next(0);
        let two_to_rot = env.coeff(0); // TODO: linearization fails if not evaluated

        // Obtains the following checks:
        // word * 2^{rot} = (excess * 2^64 + shifted)
        // rotated = shifted + excess
        constraints.push(
            word * two_to_rot.clone() - (excess.clone() * two_to_64.clone() + shifted.clone()),
        );
        constraints.push(rotated - (shifted + excess.clone()));

        // Compute the bound from the crumbs and limbs
        let mut power_of_2 = T::one();
        let mut bound = T::zero();

        // Sum 2-bit limbs
        for i in (7..COLUMNS).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= T::from(4u64); // 2 bits
        }

        // Sum 12-bit limbs
        for i in (3..=6).rev() {
            bound += power_of_2.clone() * env.witness_curr(i);
            power_of_2 *= 4096u64.into(); // 12 bits
        }

        // Check that bound = excess - 2^rot + 2^64 so as to prove that excess < 2^64
        constraints.push(bound - (excess - two_to_rot + two_to_64));

        constraints
    }
}

// ROTATION WITNESS COMPUTATION

fn layout_rot64<F: PrimeField>(sum: F, curr_row: usize) -> [[Box<dyn WitnessCell<F>>; COLUMNS]; 2] {
    [
        rot_row(sum, curr_row),
        range_check_0_row("shifted", curr_row + 1),
    ]
}

fn rot_row<F: PrimeField>(sum: F, curr_row: usize) -> [Box<dyn WitnessCell<F>>; COLUMNS] {
    [
        VariableCell::create("word"),
        VariableCell::create("rotated"),
        VariableCell::create("excess"),
        /* 12-bit plookups */
        SumCopyBitsCell::create(curr_row, 2, 52, 64, sum),
        SumCopyBitsCell::create(curr_row, 2, 40, 52, sum),
        SumCopyBitsCell::create(curr_row, 2, 28, 40, sum),
        SumCopyBitsCell::create(curr_row, 2, 16, 28, sum),
        /* 2-bit crumbs */
        SumCopyBitsCell::create(curr_row, 2, 14, 16, sum),
        SumCopyBitsCell::create(curr_row, 2, 12, 14, sum),
        SumCopyBitsCell::create(curr_row, 2, 10, 12, sum),
        SumCopyBitsCell::create(curr_row, 2, 8, 10, sum),
        SumCopyBitsCell::create(curr_row, 2, 6, 8, sum),
        SumCopyBitsCell::create(curr_row, 2, 4, 6, sum),
        SumCopyBitsCell::create(curr_row, 2, 2, 4, sum),
        SumCopyBitsCell::create(curr_row, 2, 0, 2, sum),
    ]
}

fn init_rot64<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    curr_row: usize,
    word: F,
    rotated: F,
    excess: F,
    shifted: F,
    bound: F,
) {
    let rot_rows = layout_rot64(bound, curr_row);
    witness::init(
        witness,
        curr_row,
        &rot_rows,
        &variable_map!["word" => word, "rotated" => rotated, "excess" => excess, "shifted" => shifted],
    );
}

/// Extends the rot rows to the full witness
pub fn extend_rot_rows<F: PrimeField>(
    witness: &mut [Vec<F>; COLUMNS],
    word: F,
    rotated: F,
    excess: F,
    shifted: F,
    bound: F,
) {
    let rot_row = witness[0].len();
    let rot_witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero(); 2]);
    for col in 0..COLUMNS {
        witness[col].extend(rot_witness[col].iter());
    }
    init_rot64(witness, rot_row, word, rotated, excess, shifted, bound);
}

/// Create a rotation witness
/// Input: word to be rotated, rotation offset.
/// Output: witness for rotation word and initial row with all zeros
pub fn create_witness<F: PrimeField>(word: u64, rot: u32) -> [Vec<F>; COLUMNS] {
    // First generic gate with all zeros to constrain that the two most significant limbs of shifted output are zeros
    let mut witness: [Vec<F>; COLUMNS] = array::from_fn(|_| vec![F::zero()]);
    create_witness_rot(&mut witness, word, rot);
    witness
}

/// Create a rotation witness
/// Input: word to be rotated, rotation offset,
pub fn create_witness_rot<F: PrimeField>(witness: &mut [Vec<F>; COLUMNS], word: u64, rot: u32) {
    assert_ne!(rot, 0, "Rotation value must be non-zero");
    assert!(rot < 64, "Rotation value must be less than 64");

    let shifted = (word as u128 * 2u128.pow(rot) % 2u128.pow(64)) as u64;
    let excess = word / 2u64.pow(64 - rot);
    let rotated = shifted + excess;
    // Value for the added value for the bound
    let bound = 2u128.pow(64) - 2u128.pow(rot);

    extend_rot_rows(
        witness,
        F::from(word),
        F::from(rotated),
        F::from(excess),
        F::from(shifted),
        F::from(bound),
    );
}
