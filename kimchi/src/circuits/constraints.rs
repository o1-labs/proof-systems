//! This module implements Plonk circuit constraint primitive.

use crate::circuits::{
    domains::EvaluationDomains,
    gate::{self, CircuitGate, GateType, LookupInfo, LookupTable},
    polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts},
    polynomials::lookup::LookupConfiguration,
    wires::*,
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::UVPolynomial;
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use array_init::array_init;
use blake2::{Blake2b512, Digest};
use o1_utils::ExtendedEvaluations;
use oracle::poseidon::ArithmeticSpongeParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

//
// Constants
//

pub const ZK_ROWS: u64 = 3;

//
// ConstraintSystem
//

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LookupConstraintSystem<F: FftField> {
    /// Lookup tables
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_table: Vec<DP<F>>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_table8: Vec<E<F, D<F>>>,

    /// Table IDs for the lookup values.
    /// This may be `None` if all lookups originate from table 0.
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub table_ids: Option<DP<F>>,
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub table_ids8: Option<E<F, D<F>>>,

    /// Lookup selectors:
    /// For each kind of lookup-pattern, we have a selector that's
    /// 1 at the rows where that pattern should be enforced, and 0 at
    /// all other rows.
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_selectors: Vec<E<F, D<F>>>,

    /// Configuration for the lookup constraint.
    #[serde(bound = "LookupConfiguration<F>: Serialize + DeserializeOwned")]
    pub configuration: LookupConfiguration<F>,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConstraintSystem<F: FftField> {
    // Basics
    // ------
    /// number of public inputs
    pub public: usize,
    /// evaluation domains
    #[serde(bound = "EvaluationDomains<F>: Serialize + DeserializeOwned")]
    pub domain: EvaluationDomains<F>,
    /// circuit gates
    #[serde(bound = "CircuitGate<F>: Serialize + DeserializeOwned")]
    pub gates: Vec<CircuitGate<F>>,

    // Polynomials over the monomial base
    // ----------------------------------
    /// permutation polynomial array
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmam: [DP<F>; PERMUTS],
    /// zero-knowledge polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zkpm: DP<F>,

    // Coefficient polynomials. These define constant that gates can use as they like.
    // ---------------------------------------
    /// coefficients polynomials in evaluation form
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub coefficients8: [E<F, D<F>>; COLUMNS],

    // Generic constraint selector polynomials
    // ---------------------------------------
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub genericm: DP<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub psm: DP<F>,

    // Generic constraint selector polynomials
    // ---------------------------------------
    /// multiplication evaluations over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub generic4: E<F, D<F>>,

    // permutation polynomials
    // -----------------------
    /// permutation polynomial array evaluations over domain d1
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal1: [E<F, D<F>>; PERMUTS],
    /// permutation polynomial array evaluations over domain d8
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub sigmal8: [E<F, D<F>>; PERMUTS],
    /// SID polynomial
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub sid: Vec<F>,

    // Poseidon selector polynomials
    // -----------------------------
    /// poseidon selector over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ps8: E<F, D<F>>,

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition selector evaluations w over domain.d4
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub complete_addl4: E<F, D<F>>,
    /// scalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mull8: E<F, D<F>>,
    /// endoscalar multiplication selector evaluations over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emull: E<F, D<F>>,
    /// ChaCha indexes
    #[serde_as(as = "Option<[o1_utils::serialization::SerdeAs; 4]>")]
    pub chacha8: Option<[E<F, D<F>>; 4]>,
    /// EC point addition selector evaluations w over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endomul_scalar8: E<F, D<F>>,

    // Constant polynomials
    // --------------------
    /// 1-st Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l1: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d4
    // TODO(mimoo): be consistent with the paper/spec, call it L1 here or call it L0 there
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l04: E<F, D<F>>,
    /// 0-th Lagrange evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub l08: E<F, D<F>>,
    /// zero evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zero4: E<F, D<F>>,
    /// zero evaluated over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zero8: E<F, D<F>>,
    /// zero-knowledge polynomial over domain.d8
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub zkpl: E<F, D<F>>,
    /// the polynomial that vanishes on the last four rows
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub vanishes_on_last_4_rows: E<F, D<F>>,

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [F; PERMUTS],
    /// coefficient for the group endomorphism
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endo: F,

    /// random oracle argument parameters
    #[serde(skip)]
    pub fr_sponge_params: ArithmeticSpongeParams<F>,

    /// lookup constraint system
    #[serde(bound = "LookupConstraintSystem<F>: Serialize + DeserializeOwned")]
    pub lookup_constraint_system: Option<LookupConstraintSystem<F>>,
}

// TODO: move Shifts, and permutation-related functions to the permutation module

/// Shifts represent the shifts required in the permutation argument of PLONK.
/// It also caches the shifted powers of omega for optimization purposes.
pub struct Shifts<F> {
    /// The coefficients `k` (in the Plonk paper) that create a coset when multiplied with the generator of our domain.
    shifts: [F; PERMUTS],
    /// A matrix that maps all cells coordinates `{col, row}` to their shifted field element.
    /// For example the cell `{col:2, row:1}` will map to `omega * k2`,
    /// which lives in `map[2][1]`
    map: [Vec<F>; PERMUTS],
}

impl<F> Shifts<F>
where
    F: FftField + SquareRootField,
{
    /// Generates the shifts for a given domain
    pub fn new(domain: &D<F>) -> Self {
        let mut shifts = [F::zero(); PERMUTS];

        // first shift is the identity
        shifts[0] = F::one();

        // sample the other shifts
        let mut i: u32 = 7;
        for idx in 1..(PERMUTS) {
            let mut shift = Self::sample(domain, &mut i);
            // they have to be distincts
            while shifts.contains(&shift) {
                shift = Self::sample(domain, &mut i);
            }
            shifts[idx] = shift;
        }

        // create a map of cells to their shifted value
        let map: [Vec<F>; PERMUTS] =
            array_init(|i| domain.elements().map(|elm| shifts[i] * elm).collect());

        //
        Self { shifts, map }
    }

    /// retrieve the shifts
    pub fn shifts(&self) -> &[F; PERMUTS] {
        &self.shifts
    }

    /// sample coordinate shifts deterministically
    fn sample(domain: &D<F>, input: &mut u32) -> F {
        let mut h = Blake2b512::new();

        *input += 1;
        h.update(&input.to_be_bytes());

        let mut shift = F::from_random_bytes(&h.finalize()[..31])
            .expect("our field elements fit in more than 31 bytes");

        while !shift.legendre().is_qnr() || domain.evaluate_vanishing_polynomial(shift).is_zero() {
            let mut h = Blake2b512::new();
            *input += 1;
            h.update(&input.to_be_bytes());
            shift = F::from_random_bytes(&h.finalize()[..31])
                .expect("our field elements fit in more than 31 bytes");
        }
        shift
    }

    /// Returns the field element that represents a position
    fn cell_to_field(&self, &Wire { row, col }: &Wire) -> F {
        self.map[col][row]
    }
}

///

/// Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation polynomial
pub fn zk_w3<F: FftField>(domain: D<F>) -> F {
    domain.group_gen.pow(&[domain.size - (ZK_ROWS)])
}

/// Evaluates the polynomial
/// (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn eval_zk_polynomial<F: FftField>(domain: D<F>, x: F) -> F {
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    (x - w1) * (x - w2) * (x - w3)
}

/// Evaluates the polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn eval_vanishes_on_last_4_rows<F: FftField>(domain: D<F>, x: F) -> F {
    let w4 = domain.group_gen.pow(&[domain.size - (ZK_ROWS + 1)]);
    let w3 = domain.group_gen * w4;
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    (x - w1) * (x - w2) * (x - w3) * (x - w4)
}

/// The polynomial
/// (x - w^{n - 4}) (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
pub fn vanishes_on_last_4_rows<F: FftField>(domain: D<F>) -> DP<F> {
    let x = DP::from_coefficients_slice(&[F::zero(), F::one()]);
    let c = |a: F| DP::from_coefficients_slice(&[a]);
    let w4 = domain.group_gen.pow(&[domain.size - (ZK_ROWS + 1)]);
    let w3 = domain.group_gen * w4;
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;
    &(&(&x - &c(w1)) * &(&x - &c(w2))) * &(&(&x - &c(w3)) * &(&x - &c(w4)))
}

/// Computes the zero-knowledge polynomial for blinding the permutation polynomial: `(x-w^{n-k})(x-w^{n-k-1})...(x-w^n)`.
/// Currently, we use k = 3 for 2 blinding factors,
/// see <https://www.plonk.cafe/t/noob-questions-plonk-paper/73>
pub fn zk_polynomial<F: FftField>(domain: D<F>) -> DP<F> {
    let w3 = zk_w3(domain);
    let w2 = domain.group_gen * w3;
    let w1 = domain.group_gen * w2;

    // (x-w3)(x-w2)(x-w1) =
    // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
    let w1w2 = w1 * w2;
    DP::from_coefficients_slice(&[
        -w1w2 * w3,                   // 1
        w1w2 + (w1 * w3) + (w3 * w2), // x
        -w1 - w2 - w3,                // x^2
        F::one(),                     // x^3
    ])
}

/// Represents an error found when verifying a witness with a gate
#[derive(Debug)]
pub enum GateError {
    /// Some connected wires have different values
    DisconnectedWires(Wire, Wire),
    /// A public gate was incorrectly connected
    IncorrectPublic(usize),
    /// A specific gate did not verify correctly
    Custom { row: usize, err: String },
}

impl<F: FftField + SquareRootField> LookupConstraintSystem<F> {
    pub fn create(
        gates: &[CircuitGate<F>],
        lookup_tables: Vec<LookupTable<F>>,
        domain: &EvaluationDomains<F>,
    ) -> Option<Self> {
        let lookup_info = LookupInfo::<F>::create();
        match lookup_info.lookup_used(gates) {
            None => None,
            Some(lookup_used) => {
                let d1_size = domain.d1.size();

                let (lookup_selectors, gate_lookup_tables) =
                    lookup_info.selector_polynomials_and_tables(domain, gates);

                let lookup_tables: Vec<_> = gate_lookup_tables
                    .into_iter()
                    .chain(lookup_tables.into_iter())
                    .collect();

                if lookup_tables.len() > 1 {
                    panic!("Multiple lookup tables are currently not supported");
                }

                let lookup_table = lookup_tables.into_iter().next().unwrap();

                // get the last entry in each column of each table
                let dummy_lookup_value: Vec<F> = lookup_table
                    .data
                    .iter()
                    .map(|col| col[col.len() - 1])
                    .collect();
                let dummy_lookup_table_id = lookup_table.id;

                // pre-compute polynomial and evaluation form for the look up tables
                let mut lookup_table_polys: Vec<DP<F>> = vec![];
                let mut lookup_table8: Vec<E<F, D<F>>> = vec![];
                for (mut col, dummy) in lookup_table.data.into_iter().zip(&dummy_lookup_value) {
                    // pad each column to the size of the domain
                    let padding = (0..(d1_size - col.len())).map(|_| dummy);
                    col.extend(padding);
                    let poly = E::<F, D<F>>::from_vec_and_domain(col, domain.d1).interpolate();
                    let eval = poly.evaluate_over_domain_by_ref(domain.d8);
                    lookup_table_polys.push(poly);
                    lookup_table8.push(eval);
                }

                let (table_ids, table_ids8) = if lookup_table.id != 0 {
                    let table_ids = vec![gate::i32_to_field(lookup_table.id); d1_size];
                    let table_ids: DP<F> =
                        E::<F, D<F>>::from_vec_and_domain(table_ids, domain.d1).interpolate();
                    let table_ids8: E<F, D<F>> = table_ids.evaluate_over_domain_by_ref(domain.d8);
                    (Some(table_ids), Some(table_ids8))
                } else {
                    (None, None)
                };

                // generate the look up selector polynomials
                Some(Self {
                    lookup_selectors,
                    lookup_table8,
                    lookup_table: lookup_table_polys,
                    table_ids,
                    table_ids8,
                    configuration: LookupConfiguration {
                        lookup_used,
                        max_lookups_per_row: lookup_info.max_per_row as usize,
                        max_joint_size: lookup_info.max_joint_size,
                        dummy_lookup_value,
                        dummy_lookup_table_id,
                    },
                })
            }
        }
    }
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// creates a constraint system from a vector of gates ([CircuitGate]), some sponge parameters ([ArithmeticSpongeParams]), and the number of public inputs.
    pub fn create(
        mut gates: Vec<CircuitGate<F>>,
        lookup_tables: Vec<LookupTable<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self> {
        //~ 1. If the circuit is less than 2 gates, abort.
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        //~ 2. Create a domain for the circuit. That is,
        //~    compute the smallest subgroup of the field that
        //~    has order greater or equal to `n + ZK_ROWS` elements.
        let domain = EvaluationDomains::<F>::create(gates.len() + ZK_ROWS as usize)?;
        assert!(domain.d1.size > ZK_ROWS);

        //~ 3. Pad the circuit: add zero gates to reach the domain size.
        let d1_size = domain.d1.size();
        let mut padding = (gates.len()..d1_size)
            .map(|i| {
                CircuitGate::<F>::zero(array_init(|j| Wire {
                    col: WIRES[j],
                    row: i,
                }))
            })
            .collect();
        gates.append(&mut padding);

        //~ 4. sample the `PERMUTS` shifts.
        let shifts = Shifts::new(&domain.d1);

        // Precomputations
        // ===============
        // what follows are pre-computations.

        //
        // Permutation
        // -----------

        // compute permutation polynomials
        let mut sigmal1: [Vec<F>; PERMUTS] =
            array_init(|_| vec![F::zero(); domain.d1.size as usize]);

        for (row, gate) in gates.iter().enumerate() {
            for (cell, sigma) in gate.wires.iter().zip(sigmal1.iter_mut()) {
                sigma[row] = shifts.cell_to_field(cell);
            }
        }

        let sigmal1: [_; PERMUTS] = {
            let [s0, s1, s2, s3, s4, s5, s6] = sigmal1;
            [
                E::<F, D<F>>::from_vec_and_domain(s0, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s1, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s2, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s3, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s4, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s5, domain.d1),
                E::<F, D<F>>::from_vec_and_domain(s6, domain.d1),
            ]
        };

        let sigmam: [DP<F>; PERMUTS] = array_init(|i| sigmal1[i].clone().interpolate());

        let sigmal8 = array_init(|i| sigmam[i].evaluate_over_domain_by_ref(domain.d8));

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);
        let zkpl = zkpm.evaluate_over_domain_by_ref(domain.d8);

        // Gates
        // -----
        //
        // Compute each gate's polynomial as
        // the polynomial that evaluates to 1 at $g^i$
        // where $i$ is the row where a gate is active.
        // Note: gates must be mutually exclusive.

        // poseidon gate
        let psm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.ps()).collect(),
            domain.d1,
        )
        .interpolate();
        let ps8 = psm.evaluate_over_domain_by_ref(domain.d8);

        // ECC gates
        let complete_addm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| F::from((gate.typ == GateType::CompleteAdd) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let complete_addl4 = complete_addm.evaluate_over_domain_by_ref(domain.d4);

        let mulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.vbmul()).collect(),
            domain.d1,
        )
        .interpolate();
        let mull8 = mulm.evaluate_over_domain_by_ref(domain.d8);

        let emulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.endomul()).collect(),
            domain.d1,
        )
        .interpolate();
        let emull = emulm.evaluate_over_domain_by_ref(domain.d8);

        let endomul_scalarm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| F::from((gate.typ == GateType::EndoMulScalar) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let endomul_scalar8 = endomul_scalarm.evaluate_over_domain_by_ref(domain.d8);

        // double generic gate
        let genericm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| {
                    if matches!(gate.typ, GateType::Generic) {
                        F::one()
                    } else {
                        F::zero()
                    }
                })
                .collect(),
            domain.d1,
        )
        .interpolate();
        let generic4 = genericm.evaluate_over_domain_by_ref(domain.d4);

        // chacha gate
        let chacha8 = {
            use GateType::*;
            let has_chacha_gate = gates
                .iter()
                .any(|gate| matches!(gate.typ, ChaCha0 | ChaCha1 | ChaCha2 | ChaChaFinal));
            if !has_chacha_gate {
                None
            } else {
                let a: [_; 4] = array_init(|i| {
                    let g = match i {
                        0 => ChaCha0,
                        1 => ChaCha1,
                        2 => ChaCha2,
                        3 => ChaChaFinal,
                        _ => panic!("Invalid index"),
                    };
                    E::<F, D<F>>::from_vec_and_domain(
                        gates
                            .iter()
                            .map(|gate| if gate.typ == g { F::one() } else { F::zero() })
                            .collect(),
                        domain.d1,
                    )
                    .interpolate()
                    .evaluate_over_domain(domain.d8)
                });
                Some(a)
            }
        };

        //
        // Coefficient
        // -----------
        //

        // coefficient polynomial
        let coefficientsm: [_; COLUMNS] = array_init(|i| {
            let padded = gates
                .iter()
                .map(|gate| gate.coeffs.get(i).cloned().unwrap_or_else(F::zero))
                .collect();
            let eval = E::from_vec_and_domain(padded, domain.d1);
            eval.interpolate()
        });
        // TODO: This doesn't need to be degree 8 but that would require some changes in expr
        let coefficients8 = array_init(|i| coefficientsm[i].evaluate_over_domain_by_ref(domain.d8));

        //
        // Lookup
        // ------

        let lookup_constraint_system =
            LookupConstraintSystem::create(&gates, lookup_tables, &domain);

        //
        // Constant polynomials
        // --------------------

        let sid = shifts.map[0].clone();

        let l1 = DP::from_coefficients_slice(&[F::zero(), F::one()])
            .evaluate_over_domain_by_ref(domain.d8);
        // TODO: These are all unnecessary. Remove
        let l04 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d4.size as usize], domain.d4);
        let l08 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::one(); domain.d8.size as usize], domain.d8);
        let zero4 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d4.size as usize], domain.d4);
        let zero8 =
            E::<F, D<F>>::from_vec_and_domain(vec![F::zero(); domain.d8.size as usize], domain.d8);

        let vanishes_on_last_4_rows =
            vanishes_on_last_4_rows(domain.d1).evaluate_over_domain(domain.d8);

        // TODO: remove endo as a field
        let endo = F::zero();

        Some(ConstraintSystem {
            chacha8,
            endomul_scalar8,
            domain,
            public,
            sid,
            sigmal1,
            sigmal8,
            sigmam,
            genericm,
            generic4,
            coefficients8,
            ps8,
            psm,
            complete_addl4,
            mull8,
            emull,
            l1,
            l04,
            l08,
            zero4,
            zero8,
            zkpl,
            zkpm,
            vanishes_on_last_4_rows,
            gates,
            shift: shifts.shifts,
            endo,
            fr_sponge_params,
            lookup_constraint_system,
        })
    }

    /// This function verifies the consistency of the wire
    /// assignements (witness) against the constraints
    ///     witness: wire assignement witness
    ///     RETURN: verification status
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS], public: &[F]) -> Result<(), GateError> {
        // pad the witness
        let pad = vec![F::zero(); self.domain.d1.size as usize - witness[0].len()];
        let witness: [Vec<F>; COLUMNS] = array_init(|i| {
            let mut w = witness[i].to_vec();
            w.extend_from_slice(&pad);
            w
        });

        // check each rows' wiring
        for (row, gate) in self.gates.iter().enumerate() {
            // check if wires are connected
            for col in 0..PERMUTS {
                let wire = gate.wires[col];

                if wire.col >= PERMUTS {
                    return Err(GateError::Custom {
                        row,
                        err: format!(
                            "a wire can only be connected to the first {} columns",
                            PERMUTS
                        ),
                    });
                }

                if witness[col][row] != witness[wire.col][wire.row] {
                    return Err(GateError::DisconnectedWires(
                        Wire { col, row },
                        Wire {
                            col: wire.col,
                            row: wire.row,
                        },
                    ));
                }
            }

            // for public gates, only the left wire is toggled
            if row < self.public && gate.coeffs[0] != F::one() {
                return Err(GateError::IncorrectPublic(row));
            }

            // check the gate's satisfiability
            gate.verify(row, &witness, self, public)
                .map_err(|err| GateError::Custom { row, err })?;
        }

        // all good!
        Ok(())
    }

    /// evaluate witness polynomials over domains
    pub fn evaluate(&self, w: &[DP<F>; COLUMNS], z: &DP<F>) -> WitnessOverDomains<F> {
        // compute shifted witness polynomials
        let w8: [E<F, D<F>>; COLUMNS] =
            array_init(|i| w[i].evaluate_over_domain_by_ref(self.domain.d8));
        let z8 = z.evaluate_over_domain_by_ref(self.domain.d8);

        let w4: [E<F, D<F>>; COLUMNS] = array_init(|i| {
            E::<F, D<F>>::from_vec_and_domain(
                (0..self.domain.d4.size)
                    .map(|j| w8[i].evals[2 * j as usize])
                    .collect(),
                self.domain.d4,
            )
        });
        let z4 = DP::<F>::zero().evaluate_over_domain_by_ref(D::<F>::new(1).unwrap());

        WitnessOverDomains {
            d4: WitnessShifts {
                next: WitnessEvals {
                    w: array_init(|i| w4[i].shift(4)),
                    // TODO(mimoo): change z to an Option? Or maybe not, we might actually need this dummy evaluation in the aggregated evaluation proof
                    z: z4.clone(), // dummy evaluation
                },
                this: WitnessEvals {
                    w: w4,
                    z: z4, // dummy evaluation
                },
            },
            d8: WitnessShifts {
                next: WitnessEvals {
                    w: array_init(|i| w8[i].shift(8)),
                    z: z8.shift(8),
                },
                this: WitnessEvals { w: w8, z: z8 },
            },
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_ff::{FftField, SquareRootField};
    use mina_curves::pasta::fp::Fp;

    impl<F: FftField + SquareRootField> ConstraintSystem<F> {
        pub fn for_testing(
            sponge_params: ArithmeticSpongeParams<F>,
            gates: Vec<CircuitGate<F>>,
        ) -> Self {
            let public = 0;
            ConstraintSystem::<F>::create(gates, vec![], sponge_params, public).unwrap()
        }
    }

    impl ConstraintSystem<Fp> {
        pub fn fp_for_testing(gates: Vec<CircuitGate<Fp>>) -> Self {
            let fp_sponge_params = oracle::pasta::fp_kimchi::params();
            Self::for_testing(fp_sponge_params, gates)
        }
    }
}
