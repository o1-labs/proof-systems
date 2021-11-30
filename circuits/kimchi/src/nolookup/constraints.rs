/*****************************************************************************************************************

This source file implements Plonk circuit constraint primitive.

*****************************************************************************************************************/

use crate::domains::EvaluationDomains;
use crate::gate::{CircuitGate, GateType, LookupInfo, LookupTable};
pub use crate::polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts};
use crate::wires::*;
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::UVPolynomial;
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use array_init::array_init;
use blake2::{Blake2b, Digest};
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
    /// coefficients polynomials in coefficient form
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; COLUMNS]")]
    pub coefficientsm: [DP<F>; COLUMNS],
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

    // ECC arithmetic selector polynomials
    // -----------------------------------
    /// EC point addition constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub complete_addm: DP<F>,
    /// mulm constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub mulm: DP<F>,
    /// emulm constraint selector polynomial
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub emulm: DP<F>,
    /// endomul scalar computation
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub endomul_scalarm: DP<F>,

    // Runtime lookup polynomials
    // --------------------------
    /// the constant indexer polynomial, f(w^i) = i
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub indexer: DP<F>,

    //
    // Polynomials over lagrange base
    //

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

    // Runtime lookup polynomials
    // --------------------------
    /// Lookup index
    #[serde_as(as = "Option<o1_utils::serialization::SerdeAs>")]
    pub lookup8: Option<E<F, D<F>>>,
    /// the constant indexer polynomial, f(w^i) = i
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub indexer8: E<F, D<F>>,

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

    /// Lookup tables
    // TODO: this should be one big Option<Lookup>
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub dummy_lookup_values: Vec<F>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_tables: Vec<DP<F>>,
    #[serde_as(as = "Vec<o1_utils::serialization::SerdeAs>")]
    pub lookup_tables8: Vec<E<F, D<F>>>,
    pub lookup_table_length: usize,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub lookup_table_ids: DP<F>,
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub lookup_table_ids8: E<F, D<F>>,

    /// Lookup selectors:
    /// For each kind of lookup-pattern, we have a selector that's
    /// 1 at the rows where that pattern should be enforced, and 0 at
    /// all other rows.
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub lookup_selectors: Vec<E<F, D<F>>>,
}

/// Shifts represent the shifts required in the permutation argument of PLONK.
/// It also caches the shifted powers of omega for optimization purposes.
pub struct Shifts<F> {
    /// The coefficients k that create a coset when multiplied with the generator of our domain.
    shifts: [F; PERMUTS],
    /// A matrix that maps all cells coordinates {col, row} to their shifted field element.
    /// For example the cell {col:2, row:1} will map to omega * k2,
    /// which lives in map[2][1]
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
        let mut h = Blake2b::new();

        *input += 1;
        h.update(&input.to_be_bytes());

        let mut shift = F::from_random_bytes(&h.finalize()[..31])
            .expect("our field elements fit in more than 31 bytes");

        while !shift.legendre().is_qnr() || domain.evaluate_vanishing_polynomial(shift).is_zero() {
            let mut h = Blake2b::new();
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

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// creates a constraint system from a vector of gates ([CircuitGate]), some sponge parameters ([ArithmeticSpongeParams]), and the number of public inputs.
    pub fn create(
        mut gates: Vec<CircuitGate<F>>,
        lookup_tables: Vec<LookupTable<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Option<Self> {
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        // +3 on gates.len() here to ensure that we have room for the zero-knowledge entries of the permutation polynomial
        // see https://minaprotocol.com/blog/a-more-efficient-approach-to-zero-knowledge-for-plonk
        let domain = EvaluationDomains::<F>::create(gates.len() + ZK_ROWS as usize)?;
        assert!(domain.d1.size > ZK_ROWS);

        // pre-compute all the elements
        let mut sid = domain.d1.elements().collect::<Vec<_>>();

        // pad the rows: add zero gates to reach the domain size
        let d1_size = domain.d1.size();
        let mut padding = (gates.len()..d1_size)
            .map(|i| {
                CircuitGate::<F>::zero(
                    i,
                    array_init(|j| Wire {
                        col: WIRES[j],
                        row: i,
                    }),
                )
            })
            .collect();
        gates.append(&mut padding);

        //
        // Permutation
        //

        // sample the coordinate shifts
        let shifts = Shifts::new(&domain.d1);

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

        let mut s = sid[0..2].to_vec(); // TODO(mimoo): why do we do that?
        sid.append(&mut s);

        // x^3 - x^2(w1+w2+w3) + x(w1w2+w1w3+w2w3) - w1w2w3
        let zkpm = zk_polynomial(domain.d1);
        let zkpl = zkpm.evaluate_over_domain_by_ref(domain.d8);

        //
        // Gates
        //

        // compute generic constraint polynomials

        // compute poseidon constraint polynomials
        let psm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.ps()).collect(),
            domain.d1,
        )
        .interpolate();

        // compute ECC arithmetic constraint polynomials
        let complete_addm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| F::from((gate.typ == GateType::CompleteAdd) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();
        let mulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.vbmul()).collect(),
            domain.d1,
        )
        .interpolate();
        let emulm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.endomul()).collect(),
            domain.d1,
        )
        .interpolate();
        let endomul_scalarm = E::<F, D<F>>::from_vec_and_domain(
            gates
                .iter()
                .map(|gate| F::from((gate.typ == GateType::EndomulScalar) as u64))
                .collect(),
            domain.d1,
        )
        .interpolate();

        // generic constraint polynomials

        let genericm = E::<F, D<F>>::from_vec_and_domain(
            gates.iter().map(|gate| gate.generic()).collect(),
            domain.d1,
        )
        .interpolate();
        let generic4 = genericm.evaluate_over_domain_by_ref(domain.d4);

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

        let coefficientsm: [_; COLUMNS] = array_init(|i| {
            E::<F, D<F>>::from_vec_and_domain(
                gates
                    .iter()
                    .map(|gate| {
                        if i < gate.c.len() {
                            gate.c[i]
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
                domain.d1,
            )
            .interpolate()
        });
        // TODO: This doesn't need to be degree 8 but that would require some changes in expr
        let coefficients8 = array_init(|i| coefficientsm[i].evaluate_over_domain_by_ref(domain.d8));

        let ps8 = psm.evaluate_over_domain_by_ref(domain.d8);

        // ECC arithmetic constraint polynomials
        let mull8 = mulm.evaluate_over_domain_by_ref(domain.d8);
        let emull = emulm.evaluate_over_domain_by_ref(domain.d8);
        let endomul_scalar8 = endomul_scalarm.evaluate_over_domain_by_ref(domain.d8);
        let complete_addl4 = complete_addm.evaluate_over_domain_by_ref(domain.d4);

        // Runtime lookup polynomials
        let lookup8 = {
            use GateType::*;
            let has_lookup_gate = gates.iter().any(|gate| gate.typ == Lookup);
            if !has_lookup_gate {
                None
            } else {
                let a = E::<F, D<F>>::from_vec_and_domain(
                    gates
                        .iter()
                        .map(|gate| {
                            if gate.typ == Lookup {
                                F::one()
                            } else {
                                F::zero()
                            }
                        })
                        .collect(),
                    domain.d1,
                )
                .interpolate()
                .evaluate_over_domain(domain.d8);
                Some(a)
            }
        };

        let indexer = {
            // NB: The indexer is in reverse order, to allow the runtime table to be 'snakified'
            // with the lookup table
            let indexes: Vec<_> = (0..domain.d1.size - ZK_ROWS)
                .rev()
                .map(Into::into)
                .collect();
            E::<F, D<F>>::from_vec_and_domain(indexes, domain.d1).interpolate()
        };
        let indexer8 = indexer.evaluate_over_domain_by_ref(domain.d8);

        // constant polynomials
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

        // endo
        let endo = F::zero();

        //
        // Lookup
        //

        // Get the max width of all lookup tables
        let max_table_width = lookup_tables
            .iter()
            .fold(0, |max_width, LookupTable { width, .. }| {
                std::cmp::max(max_width, *width)
            });
        let mut lookup_table = vec![Vec::with_capacity(d1_size); max_table_width];
        let mut lookup_table_ids = Vec::with_capacity(d1_size);
        for table in lookup_tables.iter() {
            let table_id = {
                if table.table_id >= 0 {
                    F::from(table.table_id as u32)
                } else {
                    -F::from((-table.table_id) as u32)
                }
            };
            for row in table.values.iter() {
                if row.len() != table.width {
                    // Malformed table, widths do not match
                    None?;
                }
                lookup_table_ids.push(table_id);
                for (i, value) in row.iter().enumerate() {
                    lookup_table[i].push(*value);
                }
                for i in row.len()..max_table_width {
                    lookup_table[i].push(F::zero())
                }
            }
        }

        let mut lookup_table_length = 0;

        // Pad with zeros as needed
        if max_table_width > 0 {
            lookup_table_length = lookup_table[0].len();
            if lookup_table_length > d1_size - (ZK_ROWS as usize) {
                // Too many values across tables
                None?
            }
            for _ in lookup_table_length..d1_size - (ZK_ROWS as usize) {
                lookup_table_ids.push(F::zero());
                for j in 0..max_table_width {
                    lookup_table[j].push(F::zero())
                }
            }
        }

        let dummy_lookup_values: Vec<_> = lookup_table
            .iter()
            .map(|tbl| {
                let len = tbl.len();
                tbl[len - 1]
            })
            .collect();

        let lookup_table_polys: Vec<DP<F>> = lookup_table
            .into_iter()
            .map(|tbl| E::<F, D<F>>::from_vec_and_domain(tbl, domain.d1).interpolate())
            .collect();

        let lookup_tables8: Vec<E<F, D<F>>> = lookup_table_polys
            .iter()
            .map(|poly| poly.evaluate_over_domain_by_ref(domain.d8))
            .collect();

        for _ in (d1_size - ZK_ROWS as usize)..d1_size {
            lookup_table_ids.push(F::one());
        }

        let lookup_table_id_polys =
            E::<F, D<F>>::from_vec_and_domain(lookup_table_ids, domain.d1).interpolate();
        let lookup_table_ids8 = lookup_table_id_polys.evaluate_over_domain_by_ref(domain.d8);

        // generate the look up selector polynomials if any lookup-based gate is being used in the circuit
        let lookup_info = LookupInfo::<F>::create();
        let lookup_selectors = if lookup_info.lookup_used(&gates).is_some() {
            LookupInfo::<F>::create().selector_polynomials(domain, &gates)
        } else {
            vec![]
        };

        //
        // return result
        //

        Some(ConstraintSystem {
            chacha8,
            lookup_selectors,
            dummy_lookup_values,
            lookup_table_length,
            lookup_tables8,
            lookup_tables: lookup_table_polys,
            lookup_table_ids: lookup_table_id_polys,
            lookup_table_ids8,
            endomul_scalar8,
            endomul_scalarm,
            domain,
            public,
            sid,
            sigmal1,
            sigmal8,
            sigmam,
            genericm,
            generic4,
            coefficientsm,
            coefficients8,
            ps8,
            psm,
            complete_addm,
            complete_addl4,
            mull8,
            mulm,
            emull,
            emulm,
            l1,
            l04,
            l08,
            zero4,
            zero8,
            zkpl,
            zkpm,
            vanishes_on_last_4_rows,
            indexer,
            indexer8,
            lookup8,
            gates,
            shift: shifts.shifts,
            endo,
            fr_sponge_params,
        })
    }

    /// This function verifies the consistency of the wire
    /// assignements (witness) against the constraints
    ///     witness: wire assignement witness
    ///     RETURN: verification status
    pub fn verify(&self, witness: &[Vec<F>; COLUMNS]) -> Result<(), GateError> {
        let left_wire = vec![F::one(), F::zero(), F::zero(), F::zero(), F::zero()];

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
            if row < self.public && gate.c != left_wire {
                return Err(GateError::IncorrectPublic(row));
            }

            // check the gate's satisfiability
            gate.verify(&witness, self)
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
            let fp_sponge_params = oracle::pasta::fp::params();
            Self::for_testing(fp_sponge_params, gates)
        }
    }
}
