//! This module implements the verifier index as [`VerifierIndex`].
//! You can derive this struct from the [`ProverIndex`] struct.

use crate::{
    alphas::Alphas,
    circuits::{
        berkeley_columns::Column,
        expr::{Linearization, PolishToken},
        lookup::{index::LookupSelectors, lookups::LookupInfo},
        polynomials::permutation::{vanishes_on_last_n_rows, zk_w},
        wires::{COLUMNS, PERMUTS},
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use ark_ff::{One, PrimeField};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use mina_poseidon::FqSponge;
use once_cell::sync::OnceCell;
use poly_commitment::{
    commitment::{CommitmentCurve, PolyComm},
    OpenProof, SRS as _,
};
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
    pub joint_lookup_used: bool,
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
pub struct VerifierIndex<G: KimchiCurve, OpeningProof: OpenProof<G>> {
    /// evaluation domain
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub domain: D<G::ScalarField>,
    /// maximal size of polynomial section
    pub max_poly_size: usize,
    /// the number of randomized rows to achieve zero knowledge
    pub zk_rows: u64,
    /// polynomial commitment keys
    #[serde(skip)]
    #[serde(bound(deserialize = "OpeningProof::SRS: Default"))]
    pub srs: Arc<OpeningProof::SRS>,
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

    /// RangeCheck0 polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check0_comm: Option<PolyComm<G>>,

    /// RangeCheck1 polynomial commitments
    #[serde(bound = "Option<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check1_comm: Option<PolyComm<G>>,

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
    pub permutation_vanishing_polynomial_m: OnceCell<DensePolynomial<G::ScalarField>>,
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
    pub linearization: Linearization<Vec<PolishToken<G::ScalarField, Column>>, Column>,
    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<G::ScalarField>,
}
//~spec:endcode

impl<G: KimchiCurve, OpeningProof: OpenProof<G>> ProverIndex<G, OpeningProof>
where
    G::BaseField: PrimeField,
{
    /// Produces the [`VerifierIndex`] from the prover's [`ProverIndex`].
    ///
    /// # Panics
    ///
    /// Will panic if `srs` cannot be in `cell`.
    pub fn verifier_index(&self) -> VerifierIndex<G, OpeningProof>
    where
        VerifierIndex<G, OpeningProof>: Clone,
    {
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
                    joint_lookup_used: cs.configuration.lookup_info.features.joint_lookup_used,
                    lookup_info: cs.configuration.lookup_info,
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
            zk_rows: self.cs.zk_rows,
            powers_of_alpha: self.powers_of_alpha.clone(),
            public: self.cs.public,
            prev_challenges: self.cs.prev_challenges,
            srs: Arc::clone(&self.srs),

            sigma_comm: array::from_fn(|i| {
                self.srs.commit_evaluations_non_hiding(
                    domain,
                    &self.column_evaluations.permutation_coefficients8[i],
                )
            }),
            coefficients_comm: array::from_fn(|i| {
                self.srs.commit_evaluations_non_hiding(
                    domain,
                    &self.column_evaluations.coefficients8[i],
                )
            }),
            generic_comm: mask_fixed(
                self.srs.commit_evaluations_non_hiding(
                    domain,
                    &self.column_evaluations.generic_selector4,
                ),
            ),

            psm_comm: mask_fixed(self.srs.commit_evaluations_non_hiding(
                domain,
                &self.column_evaluations.poseidon_selector8,
            )),

            complete_add_comm: mask_fixed(self.srs.commit_evaluations_non_hiding(
                domain,
                &self.column_evaluations.complete_add_selector4,
            )),
            mul_comm: mask_fixed(
                self.srs
                    .commit_evaluations_non_hiding(domain, &self.column_evaluations.mul_selector8),
            ),
            emul_comm: mask_fixed(
                self.srs
                    .commit_evaluations_non_hiding(domain, &self.column_evaluations.emul_selector8),
            ),

            endomul_scalar_comm: mask_fixed(self.srs.commit_evaluations_non_hiding(
                domain,
                &self.column_evaluations.endomul_scalar_selector8,
            )),

            range_check0_comm: self
                .column_evaluations
                .range_check0_selector8
                .as_ref()
                .map(|eval8| self.srs.commit_evaluations_non_hiding(domain, eval8)),

            range_check1_comm: self
                .column_evaluations
                .range_check1_selector8
                .as_ref()
                .map(|eval8| self.srs.commit_evaluations_non_hiding(domain, eval8)),

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
            permutation_vanishing_polynomial_m: {
                let cell = OnceCell::new();
                cell.set(
                    self.cs
                        .precomputations()
                        .permutation_vanishing_polynomial_m
                        .clone(),
                )
                .unwrap();
                cell
            },
            w: {
                let cell = OnceCell::new();
                cell.set(zk_w(self.cs.domain.d1, self.cs.zk_rows)).unwrap();
                cell
            },
            endo: self.cs.endo,
            lookup_index,
            linearization: self.linearization.clone(),
        }
    }
}

impl<G: KimchiCurve, OpeningProof: OpenProof<G>> VerifierIndex<G, OpeningProof> {
    /// Gets srs from [`VerifierIndex`] lazily
    pub fn srs(&self) -> &Arc<OpeningProof::SRS>
    where
        G::BaseField: PrimeField,
    {
        &self.srs
    }

    /// Gets permutation_vanishing_polynomial_m from [`VerifierIndex`] lazily
    pub fn permutation_vanishing_polynomial_m(&self) -> &DensePolynomial<G::ScalarField> {
        self.permutation_vanishing_polynomial_m
            .get_or_init(|| vanishes_on_last_n_rows(self.domain, self.zk_rows))
    }

    /// Gets w from [`VerifierIndex`] lazily
    pub fn w(&self) -> &G::ScalarField {
        self.w.get_or_init(|| zk_w(self.domain, self.zk_rows))
    }

    /// Deserializes a [`VerifierIndex`] from a file, given a pointer to an SRS and an optional offset in the file.
    ///
    /// # Errors
    ///
    /// Will give error if it fails to deserialize from file or unable to set `srs` in `verifier_index`.
    pub fn from_file(
        srs: Arc<OpeningProof::SRS>,
        path: &Path,
        offset: Option<u64>,
        // TODO: we shouldn't have to pass these
        endo: G::ScalarField,
    ) -> Result<Self, String>
    where
        OpeningProof::SRS: Default,
    {
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
        verifier_index.srs = srs;
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
        let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());
        // We fully expand this to make the compiler check that we aren't missing any commitments
        let VerifierIndex {
            domain: _,
            max_poly_size: _,
            zk_rows: _,
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
            range_check0_comm,
            range_check1_comm,
            foreign_field_add_comm,
            foreign_field_mul_comm,
            xor_comm,
            rot_comm,

            // Lookup index; optional
            lookup_index,

            shift: _,
            permutation_vanishing_polynomial_m: _,
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

        if let Some(range_check0_comm) = range_check0_comm {
            fq_sponge.absorb_g(&range_check0_comm.unshifted);
        }

        if let Some(range_check1_comm) = range_check1_comm {
            fq_sponge.absorb_g(&range_check1_comm.unshifted);
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
            joint_lookup_used: _,
            lookup_info: _,
            lookup_table,
            table_ids,
            runtime_tables_selector,

            lookup_selectors:
                LookupSelectors {
                    xor,
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
