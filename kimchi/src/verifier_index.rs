//! This module implements the verifier index as [`VerifierIndex`].
//! You can derive this struct from the [`ProverIndex`] struct.

use crate::{
    alphas::Alphas,
    circuits::{
        expr::{Linearization, PolishToken},
        lookup::{
            index::LookupSelectors,
            lookups::{LookupInfo, LookupsUsed},
        },
        polynomials::{
            permutation::{zk_polynomial, zk_w3},
            range_check,
        },
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    error::VerifierIndexError,
    prover_index::ProverIndex,
};
use ark_ff::{One, PrimeField};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::SRS,
};
use mina_poseidon::FqSponge;
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::array;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek, SeekFrom::Start},
    path::Path,
    sync::Arc,
};

//~spec:startcode
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LookupVerifierIndex<G: CommitmentCurve> {
    pub lookup_used: LookupsUsed,
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_table: Vec<PolyComm<G>>,
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_selectors: LookupSelectors<PolyComm<G>>,

    /// Table IDs for the lookup values.
    /// This may be `None` if all lookups originate from table 0.
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub table_ids: Option<PolyComm<G>>,

    /// Information about the specific lookups used
    pub lookup_info: LookupInfo,

    /// An optional selector polynomial for runtime tables
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub runtime_tables_selector: Option<PolyComm<G>>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifierIndex<G: KimchiCurve> {
    /// evaluation domain
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub domain: D<G::ScalarField>,
    /// maximal size of polynomial section
    pub max_poly_size: usize,
    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: OnceCell<Arc<SRS<G>>>,
    /// number of public inputs
    pub public: usize,
    /// number of previous evaluation challenges, for recursive proving
    pub prev_challenges: usize,

    // index polynomial commitments
    /// permutation commitment array
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub sigma_comm: [PolyComm<G>; PERMUTS],
    /// coefficient commitment array
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub coefficients_comm: [PolyComm<G>; COLUMNS],
    /// coefficient commitment array
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub generic_comm: PolyComm<G>,

    // poseidon polynomial commitments
    /// poseidon constraint selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub psm_comm: PolyComm<G>,

    // ECC arithmetic polynomial commitments
    /// EC addition selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub complete_add_comm: PolyComm<G>,
    /// EC variable base scalar multiplication selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub mul_comm: PolyComm<G>,
    /// endoscalar multiplication selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub emul_comm: PolyComm<G>,
    /// endoscalar multiplication scalar computation selector polynomial commitment
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub endomul_scalar_comm: PolyComm<G>,

    /// Chacha polynomial commitments
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub chacha_comm: Option<[PolyComm<G>; 4]>,

    /// Range check polynomial commitments
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub range_check_comm: Option<[PolyComm<G>; range_check::gadget::GATE_COUNT]>,

    /// Foreign field addition gates polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub foreign_field_add_comm: Option<PolyComm<G>>,

    /// Foreign field multiplication gates polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub foreign_field_mul_comm: Option<PolyComm<G>>,

    /// Xor commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub xor_comm: Option<PolyComm<G>>,

    /// Rot commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub rot_comm: Option<PolyComm<G>>,

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [G::ScalarField; PERMUTS],
    /// zero-knowledge polynomial
    #[serde(skip)]
    pub zkpm: OnceCell<DensePolynomial<G::ScalarField>>,
    // TODO(mimoo): isn't this redundant with domain.d1.group_gen ?
    /// domain offset for zero-knowledge
    #[serde(skip)]
    pub w: OnceCell<G::ScalarField>,
    /// endoscalar coefficient
    #[serde(skip)]
    pub endo: G::ScalarField,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_index: Option<LookupVerifierIndex<G>>,

    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<G::ScalarField>>>,
    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<G::ScalarField>,
}
//~spec:endcode

impl<G: KimchiCurve> ProverIndex<G> {
    /// Produces the [`VerifierIndex`] from the prover's [`ProverIndex`].
    ///
    /// # Panics
    ///
    /// Will panic if `srs` cannot be in `cell`.
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        if let Some(verifier_index) = &self.verifier_index {
            return verifier_index.clone();
        }

        let mask_fixed = |commitment: PolyComm<G>| {
            let blinders = commitment.map(|_| G::ScalarField::one());
            self.srs
                .mask_custom(commitment, &blinders)
                .unwrap()
                .commitment
        };

        let domain = self.cs.domain.d1;

        let lookup_index = {
            self.cs
                .lookup_constraint_system
                .as_ref()
                .map(|cs| LookupVerifierIndex {
                    lookup_used: cs.configuration.lookup_used,
                    lookup_info: cs.configuration.lookup_info.clone(),
                    lookup_selectors: cs
                        .lookup_selectors
                        .as_ref()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e)),
                    lookup_table: cs
                        .lookup_table8
                        .iter()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e))
                        .collect(),
                    table_ids: cs.table_ids8.as_ref().map(|table_ids8| {
                        self.srs.commit_evaluations_non_hiding(domain, table_ids8)
                    }),
                    runtime_tables_selector: cs
                        .runtime_selector
                        .as_ref()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e)),
                })
        };

        // TODO: Switch to commit_evaluations for all index polys
        VerifierIndex {
            domain,
            max_poly_size: self.max_poly_size,
            powers_of_alpha: self.powers_of_alpha.clone(),
            public: self.cs.public,
            prev_challenges: self.cs.prev_challenges,
            srs: {
                let cell = OnceCell::new();
                cell.set(Arc::clone(&self.srs)).unwrap();
                cell
            },

            sigma_comm: array::from_fn(|i| {
                self.srs.commit_non_hiding(
                    &self.evaluated_column_coefficients.permutation_coefficients[i],
                    None,
                )
            }),
            coefficients_comm: array::from_fn(|i| {
                self.srs.commit_evaluations_non_hiding(
                    domain,
                    &self.column_evaluations.coefficients8[i],
                )
            }),
            generic_comm: mask_fixed(
                self.srs
                    .commit_non_hiding(&self.evaluated_column_coefficients.generic_selector, None),
            ),

            psm_comm: mask_fixed(
                self.srs
                    .commit_non_hiding(&self.evaluated_column_coefficients.poseidon_selector, None),
            ),

            complete_add_comm: self.srs.commit_evaluations_non_hiding(
                domain,
                &self.column_evaluations.complete_add_selector4,
            ),
            mul_comm: self
                .srs
                .commit_evaluations_non_hiding(domain, &self.column_evaluations.mul_selector8),
            emul_comm: self
                .srs
                .commit_evaluations_non_hiding(domain, &self.column_evaluations.emul_selector8),

            endomul_scalar_comm: self.srs.commit_evaluations_non_hiding(
                domain,
                &self.column_evaluations.endomul_scalar_selector8,
            ),

            chacha_comm: self
                .column_evaluations
                .chacha_selectors8
                .as_ref()
                .map(|c| array::from_fn(|i| self.srs.commit_evaluations_non_hiding(domain, &c[i]))),

            range_check_comm: self.column_evaluations.range_check_selectors8.as_ref().map(
                |evals8| {
                    array::from_fn(|i| self.srs.commit_evaluations_non_hiding(domain, &evals8[i]))
                },
            ),

            foreign_field_add_comm: self
                .column_evaluations
                .foreign_field_add_selector8
                .as_ref()
                .map(|eval8| self.srs.commit_evaluations_non_hiding(domain, eval8)),

            foreign_field_mul_comm: self
                .column_evaluations
                .foreign_field_mul_selector8
                .as_ref()
                .map(|eval8| self.srs.commit_evaluations_non_hiding(domain, eval8)),
            xor_comm: self
                .column_evaluations
                .xor_selector8
                .as_ref()
                .map(|eval8| self.srs.commit_evaluations_non_hiding(domain, eval8)),
            rot_comm: self
                .column_evaluations
                .rot_selector8
                .as_ref()
                .map(|eval8| self.srs.commit_evaluations_non_hiding(domain, eval8)),

            shift: self.cs.shift,
            zkpm: {
                let cell = OnceCell::new();
                cell.set(self.cs.precomputations().zkpm.clone()).unwrap();
                cell
            },
            w: {
                let cell = OnceCell::new();
                cell.set(zk_w3(self.cs.domain.d1)).unwrap();
                cell
            },
            endo: self.cs.endo,
            lookup_index,
            linearization: self.linearization.clone(),
        }
    }
}

impl<G: KimchiCurve> VerifierIndex<G> {
    /// Gets srs from [`VerifierIndex`] lazily
    pub fn srs(&self) -> &Arc<SRS<G>>
    where
        G::BaseField: PrimeField,
    {
        self.srs.get_or_init(|| {
            let mut srs = SRS::<G>::create(self.max_poly_size);
            srs.add_lagrange_basis(self.domain);
            Arc::new(srs)
        })
    }

    /// Gets zkpm from [`VerifierIndex`] lazily
    pub fn zkpm(&self) -> &DensePolynomial<G::ScalarField> {
        self.zkpm.get_or_init(|| zk_polynomial(self.domain))
    }

    /// Gets w from [`VerifierIndex`] lazily
    pub fn w(&self) -> &G::ScalarField {
        self.w.get_or_init(|| zk_w3(self.domain))
    }

    /// Deserializes a [`VerifierIndex`] from a file, given a pointer to an SRS and an optional offset in the file.
    ///
    /// # Errors
    ///
    /// Will give error if it fails to deserialize from file or unable to set `srs` in `verifier_index`.
    pub fn from_file(
        srs: Option<Arc<SRS<G>>>,
        path: &Path,
        offset: Option<u64>,
        // TODO: we shouldn't have to pass these
        endo: G::ScalarField,
    ) -> Result<Self, String> {
        // open file
        let file = File::open(path).map_err(|e| e.to_string())?;

        // offset
        let mut reader = BufReader::new(file);
        if let Some(offset) = offset {
            reader.seek(Start(offset)).map_err(|e| e.to_string())?;
        }

        // deserialize
        let mut verifier_index = Self::deserialize(&mut rmp_serde::Deserializer::new(reader))
            .map_err(|e| e.to_string())?;

        // fill in the rest
        if let Some(srs) = srs {
            verifier_index
                .srs
                .set(srs)
                .map_err(|_| VerifierIndexError::SRSHasBeenSet.to_string())?;
        };

        verifier_index.endo = endo;

        Ok(verifier_index)
    }

    /// Writes a [`VerifierIndex`] to a file, potentially appending it to the already-existing content (if append is set to true)
    // TODO: append should be a bool, not an option
    /// # Errors
    ///
    /// Will give error if it fails to open a file or writes to the file.
    ///
    /// # Panics
    ///
    /// Will panic if `path` is invalid or `file serialization` has issue.
    pub fn to_file(&self, path: &Path, append: Option<bool>) -> Result<(), String> {
        let append = append.unwrap_or(true);
        let file = OpenOptions::new()
            .append(append)
            .open(path)
            .map_err(|e| e.to_string())?;

        let writer = BufWriter::new(file);

        self.serialize(&mut rmp_serde::Serializer::new(writer))
            .map_err(|e| e.to_string())
    }

    /// Compute the digest of the [`VerifierIndex`], which can be used for the Fiat-Shamir
    /// transformation while proving / verifying.
    pub fn digest<EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>>(
        &self,
    ) -> G::BaseField {
        let mut fq_sponge = EFqSponge::new(G::OtherCurve::sponge_params());
        // We fully expand this to make the compiler check that we aren't missing any commitments
        let VerifierIndex {
            domain: _,
            max_poly_size: _,
            srs: _,
            public: _,
            prev_challenges: _,

            // Always present
            sigma_comm,
            coefficients_comm,
            generic_comm,
            psm_comm,
            complete_add_comm,
            mul_comm,
            emul_comm,
            endomul_scalar_comm,

            // Optional gates
            chacha_comm,
            range_check_comm,
            foreign_field_add_comm,
            foreign_field_mul_comm,
            xor_comm,
            rot_comm,

            // Lookup index; optional
            lookup_index,

            shift: _,
            zkpm: _,
            w: _,
            endo: _,

            linearization: _,
            powers_of_alpha: _,
        } = &self;

        // Always present

        for comm in sigma_comm.iter() {
            fq_sponge.absorb_g(&comm.unshifted);
        }
        for comm in coefficients_comm.iter() {
            fq_sponge.absorb_g(&comm.unshifted);
        }
        fq_sponge.absorb_g(&generic_comm.unshifted);
        fq_sponge.absorb_g(&psm_comm.unshifted);
        fq_sponge.absorb_g(&complete_add_comm.unshifted);
        fq_sponge.absorb_g(&mul_comm.unshifted);
        fq_sponge.absorb_g(&emul_comm.unshifted);
        fq_sponge.absorb_g(&endomul_scalar_comm.unshifted);

        // Optional gates

        if let Some(chacha_comm) = chacha_comm {
            for chacha_comm in chacha_comm {
                fq_sponge.absorb_g(&chacha_comm.unshifted);
            }
        }
        if let Some(range_check_comm) = range_check_comm {
            for range_check_comm in range_check_comm {
                fq_sponge.absorb_g(&range_check_comm.unshifted);
            }
        }
        if let Some(foreign_field_mul_comm) = foreign_field_mul_comm {
            fq_sponge.absorb_g(&foreign_field_mul_comm.unshifted);
        }
        if let Some(foreign_field_add_comm) = foreign_field_add_comm {
            fq_sponge.absorb_g(&foreign_field_add_comm.unshifted);
        }

        if let Some(xor_comm) = xor_comm {
            fq_sponge.absorb_g(&xor_comm.unshifted);
        }

        if let Some(rot_comm) = rot_comm {
            fq_sponge.absorb_g(&rot_comm.unshifted);
        }

        // Lookup index; optional

        if let Some(LookupVerifierIndex {
            lookup_used: _,
            lookup_info: _,
            lookup_table,
            table_ids,
            runtime_tables_selector,

            lookup_selectors:
                LookupSelectors {
                    xor,
                    chacha_final,
                    lookup,
                    range_check,
                    ffmul,
                },
        }) = lookup_index
        {
            for entry in lookup_table {
                fq_sponge.absorb_g(&entry.unshifted);
            }
            if let Some(table_ids) = table_ids {
                fq_sponge.absorb_g(&table_ids.unshifted);
            }
            if let Some(runtime_tables_selector) = runtime_tables_selector {
                fq_sponge.absorb_g(&runtime_tables_selector.unshifted);
            }

            if let Some(xor) = xor {
                fq_sponge.absorb_g(&xor.unshifted);
            }
            if let Some(chacha_final) = chacha_final {
                fq_sponge.absorb_g(&chacha_final.unshifted);
            }
            if let Some(lookup) = lookup {
                fq_sponge.absorb_g(&lookup.unshifted);
            }
            if let Some(range_check) = range_check {
                fq_sponge.absorb_g(&range_check.unshifted);
            }
            if let Some(ffmul) = ffmul {
                fq_sponge.absorb_g(&ffmul.unshifted);
            }
        }
        fq_sponge.digest_fq()
    }
}
