//! This module implements Plonk circuit constraint primitive.
use crate::{
    circuits::{
        domain_constant_evaluation::DomainConstantEvaluations,
        domains::EvaluationDomains,
        gate::{CircuitGate, GateType},
        lookup::{
            constraints::{domain_for_tables, max_num_entries},
            tables::{get_table, GateLookupTable},
        },
        polynomial::{WitnessEvals, WitnessOverDomains, WitnessShifts},
        wires::*,
    },
    error::SetupError,
};
use ark_ff::{FftField, SquareRootField, Zero};
use ark_poly::{
    univariate::DensePolynomial as DP, EvaluationDomain, Evaluations as E,
    Radix2EvaluationDomain as D,
};
use array_init::array_init;
use blake2::{Blake2b512, Digest};
use itertools::repeat_n;
use o1_utils::{field_helpers::i32_to_field, ExtendedEvaluations};
use once_cell::sync::OnceCell;
use oracle::poseidon::ArithmeticSpongeParams;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::sync::Arc;
use thiserror::Error;

use super::{
    lookup::{
        constraints::LookupConfiguration,
        lookups::{JointLookup, LookupInfo},
        tables::LookupTable,
    },
    polynomials::permutation::ZK_ROWS,
};

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
    pub configuration: LookupConfiguration,
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

    /// precomputes
    #[serde(skip)]
    precomputations: OnceCell<Arc<DomainConstantEvaluations<F>>>,
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

/// Represents an error found when computing the lookup constraint system
#[derive(Error, Debug)]
pub enum LookupError {
    /// One of the lookup tables has columns of different lengths
    #[error("Inconsisten table length")]
    InconsistentTableLength,
    /// The combined lookup table is larger than allowed by the domain size
    #[error("Lookup table too long")]
    LookupTableTooLong {
        length: usize,
        maximum_allowed: usize,
    },
}

impl<F: FftField + SquareRootField> LookupConstraintSystem<F> {
    pub fn create(
        gates: &[CircuitGate<F>],
        lookup_tables: Vec<LookupTable<F>>,
        lookup_info: LookupInfo<F>,
        configuration: LookupConfiguration,
        domain: &EvaluationDomains<F>,
    ) -> Result<Self, LookupError> {
        let d1_size = domain.d1.size();

        // obtain the lookup selectors
        let lookup_selectors = lookup_info.selector_polynomials(domain, gates);

        // Get the max width of all lookup tables
        let max_table_width = lookup_tables
            .iter()
            .map(|table| table.data.len())
            .max()
            .unwrap_or(0);

        // create the big concatenated table (including the table id)
        let mut lookup_table = vec![Vec::with_capacity(d1_size); max_table_width];
        let mut table_ids: Vec<F> = Vec::with_capacity(d1_size);

        for table in lookup_tables.iter() {
            let table_len = table.data[0].len();

            // Update table IDs
            let table_id: F = i32_to_field(table.id);
            table_ids.extend(repeat_n(table_id, table_len));

            // Update lookup_table values
            for (col_idx, col) in table.data.iter().enumerate() {
                if col.len() != table_len {
                    return Err(LookupError::InconsistentTableLength);
                }
                lookup_table[col_idx].extend(col);
            }

            // Fill in any unused columns with 0 to match the dummy value
            for lookup_table in lookup_table.iter_mut().skip(table.data.len()) {
                lookup_table.extend(repeat_n(F::zero(), table_len))
            }
        }

        // Make sure we have space
        // Note: this error should be converted to an assert, as this shouldn't happened since we padded the circuit to the correct length
        let max_num_entries = max_num_entries(d1_size);

        if lookup_table[0].len() > max_num_entries {
            return Err(LookupError::LookupTableTooLong {
                length: lookup_table[0].len(),
                maximum_allowed: max_num_entries - 1,
            });
        }

        // Pad up to the end of the table with the dummy value.
        lookup_table
            .iter_mut()
            .for_each(|col| col.extend(repeat_n(F::zero(), max_num_entries - col.len())));
        table_ids.extend(repeat_n(F::zero(), max_num_entries - table_ids.len()));

        // pre-compute polynomial and evaluation form for the look up tables
        let mut lookup_table_polys: Vec<DP<F>> = vec![];
        let mut lookup_table8: Vec<E<F, D<F>>> = vec![];
        for col in lookup_table.into_iter() {
            let poly = E::<F, D<F>>::from_vec_and_domain(col, domain.d1).interpolate();
            let eval = poly.evaluate_over_domain_by_ref(domain.d8);
            lookup_table_polys.push(poly);
            lookup_table8.push(eval);
        }

        // pre-compute polynomial and evaluation form for the table IDs, if needed
        // NOTE: if there's only one runtime table, it will have a negative ID, and so we still need to use a table id (basically this code won't work with runtime tables)
        let (table_ids, table_ids8) = if lookup_tables.len() > 1 {
            let table_ids: DP<F> =
                E::<F, D<F>>::from_vec_and_domain(table_ids, domain.d1).interpolate();
            let table_ids8: E<F, D<F>> = table_ids.evaluate_over_domain_by_ref(domain.d8);
            (Some(table_ids), Some(table_ids8))
        } else {
            (None, None)
        };

        // generate the look up selector polynomials
        Ok(Self {
            lookup_selectors,
            lookup_table8,
            lookup_table: lookup_table_polys,
            table_ids,
            table_ids8,
            configuration,
        })
    }
}

impl<F: FftField + SquareRootField> ConstraintSystem<F> {
    /// creates a constraint system from a vector of gates ([CircuitGate]), some sponge parameters ([ArithmeticSpongeParams]), and the number of public inputs.
    pub fn create(
        gates: Vec<CircuitGate<F>>,
        lookup_tables: Vec<LookupTable<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
    ) -> Result<Self, SetupError> {
        ConstraintSystem::<F>::create_with_shared_precomputations(
            gates,
            lookup_tables,
            fr_sponge_params,
            public,
            None,
        )
    }

    /// similar to create. but this fn creates a constraint system with a shared precomputation previously created elsewhere
    pub fn create_with_shared_precomputations(
        mut gates: Vec<CircuitGate<F>>,
        lookup_tables: Vec<LookupTable<F>>,
        fr_sponge_params: ArithmeticSpongeParams<F>,
        public: usize,
        precomputations: Option<Arc<DomainConstantEvaluations<F>>>,
    ) -> Result<Self, SetupError> {
        //~ 1. If the circuit is less than 2 gates, abort.
        // for some reason we need more than 1 gate for the circuit to work, see TODO below
        assert!(gates.len() > 1);

        // if we are using lookup, create the lookup configuration now
        let lookup_info = LookupInfo::<F>::create();

        let lookup_configuration_and_tables =
            if let Some(lookup_used) = lookup_info.lookup_used(&gates) {
                // user-provided fixed tables should have negative ids
                lookup_tables.iter().for_each(|table| {
                    if table.id >= 0 {
                        panic!("custom lookup tables must have negative ids");
                    }
                });

                // get all tables used by the circuit
                let builtin_tables_used = lookup_info.tables_used(&gates);

                // convert to their actual tables
                let builtin_tables: Vec<_> =
                    builtin_tables_used.iter().cloned().map(get_table).collect();

                let mut all_tables = vec![];

                // add a dummy table only if:
                let dummy_table_needed = 
                    // - user-provided fixed tables are present
                    !lookup_tables.is_empty()
                    // - or there's either more than one table used
                    || builtin_tables_used.len() > 1
                    // - or there's a single table and it doesn't have a dummy entry
                    || !builtin_tables[0].has_zero_entry();

                if dummy_table_needed {
                    all_tables.push(get_table(GateLookupTable::Dummy));
                }

                // give each table an increasing id
                all_tables.extend(
                    builtin_tables
                        .into_iter()
                        .zip(0..) // starting at 0
                        .map(|(table, id)| LookupTable { id, ..table }),
                );

                // concatenate built-in tables with custom tables
                all_tables.extend(lookup_tables);

                // size of the concatenated tables
                let mut concatenated_table_len = 0;
                for table in &all_tables {
                    concatenated_table_len += table.data[0].len();
                }

                // pad the circuit with zero gates if the concatenated tables needs more space
                // this will ensure that the domain will be large enough to hold the concatenated tables
                let minimum_domain = domain_for_tables(concatenated_table_len);
                if gates.len() < minimum_domain {
                    let mut padding = (gates.len()..minimum_domain)
                        .map(|row| CircuitGate::<F>::zero(Wire::new(row)))
                        .collect();
                    gates.append(&mut padding);
                }

                //
                Some((
                    LookupConfiguration {
                        lookup_used,
                        used_tables: builtin_tables_used,
                        max_lookups_per_row: lookup_info.max_per_row as usize,
                        max_joint_size: lookup_info.max_joint_size,
                    },
                    all_tables,
                ))
            } else {
                None
            };

        //~ 2. Create a domain for the circuit. That is,
        //~    compute the smallest subgroup of the field that
        //~    has order greater or equal to `n + ZK_ROWS` elements.
        // Note: in the optional lookup code,
        // we might have already padded the circuit for ZK_ROWS.
        // ideally we wouldn't add room again here,
        // but it's not clear how to do this without introducing footguns.
        let domain = EvaluationDomains::<F>::create(gates.len() + ZK_ROWS as usize)?;

        assert!(domain.d1.size > ZK_ROWS);

        //~ 3. Pad the circuit: add zero gates to reach the domain size.
        let d1_size = domain.d1.size();
        let mut padding = (gates.len()..d1_size)
            .map(|row| CircuitGate::<F>::zero(Wire::new(row)))
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
            if let Some((lookup_configuration, lookup_tables)) = lookup_configuration_and_tables {
                Some(
                    LookupConstraintSystem::create(
                        &gates,
                        lookup_tables,
                        lookup_info,
                        lookup_configuration,
                        &domain,
                    )
                    .map_err(|e| SetupError::ConstraintSystem(e.to_string()))?,
                )
            } else {
                None
            };

        //
        // Other
        // -----

        let sid = shifts.map[0].clone();

        // TODO: remove endo as a field
        let endo = F::zero();

        let domain_constant_evaluation = OnceCell::new();

        let constraints = ConstraintSystem {
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
            gates,
            shift: shifts.shifts,
            endo,
            fr_sponge_params,
            lookup_constraint_system,
            precomputations: domain_constant_evaluation,
        };

        match precomputations {
            Some(t) => {
                constraints.set_precomputations(t);
            }
            None => {
                constraints.precomputations();
            }
        }

        Ok(constraints)
    }

    pub fn precomputations(&self) -> &Arc<DomainConstantEvaluations<F>> {
        self.precomputations
            .get_or_init(|| Arc::new(DomainConstantEvaluations::create(self.domain).unwrap()))
    }

    pub fn set_precomputations(&self, precomputations: Arc<DomainConstantEvaluations<F>>) {
        self.precomputations
            .set(precomputations)
            .expect("Precomputation has been set before");
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
            // not sure if theres a smarter way instead of the double unwrap, but should be fine in the test
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
