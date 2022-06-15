//! This module implements the verifier index as [VerifierIndex].
//! You can derive this struct from the [ProverIndex] struct.

use crate::alphas::Alphas;
use crate::circuits::lookup::{index::LookupSelectors, lookups::LookupsUsed};
use crate::circuits::polynomials::permutation::zk_polynomial;
use crate::circuits::polynomials::permutation::zk_w3;
use crate::circuits::{
    expr::{Linearization, PolishToken},
    wires::*,
};
use crate::error::VerifierIndexError;
use crate::prover_index::ProverIndex;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use array_init::array_init;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::SRS,
};
use o1_utils::math;
use once_cell::sync::OnceCell;
use oracle::poseidon::ArithmeticSpongeParams;
use oracle::FqSponge;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::io::SeekFrom::Start;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Seek},
    path::Path,
    sync::Arc,
};

//~spec:startcode
#[serde_as]
#[derive(Serialize, Deserialize)]
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

    /// The maximum joint size of any joint lookup in a constraint in `kinds`. This can be computed from `kinds`.
    pub max_joint_size: u32,

    /// An optional selector polynomial for runtime tables
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub runtime_tables_selector: Option<PolyComm<G>>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct VerifierIndex<G: CommitmentCurve> {
    /// evaluation domain
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub domain: D<G::ScalarField>,
    /// maximal size of polynomial section
    pub max_poly_size: usize,
    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,
    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: OnceCell<Arc<SRS<G>>>,

    /// expected size of the public input
    pub public_input_size: usize,

    /// Number of recursion accumulators to verify (if any)
    pub recursive_proofs: usize,

    /// Log2 size of the recursive circuit's domain on the other curve (or 0)
    pub recursive_log2_domain: usize,

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

    // Range check gates polynomial commitments
    #[serde(bound = "Vec<PolyComm<G>>: Serialize + DeserializeOwned")]
    pub range_check_comm: Vec<PolyComm<G>>,

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

    // random oracle argument parameters
    #[serde(skip)]
    pub fr_sponge_params: ArithmeticSpongeParams<G::ScalarField>,
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<G::BaseField>,
}
//~spec:endcode

impl<'a, G: CommitmentCurve> ProverIndex<G>
where
    G::BaseField: PrimeField,
{
    /// Produces the [VerifierIndex] from the prover's [ProverIndex].
    pub fn verifier_index(&self) -> VerifierIndex<G> {
        let domain = self.cs.domain.d1;

        let lookup_index = {
            self.cs
                .lookup_constraint_system
                .as_ref()
                .map(|cs| LookupVerifierIndex {
                    lookup_used: cs.configuration.lookup_used,
                    lookup_selectors: cs
                        .lookup_selectors
                        .as_ref()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None)),
                    lookup_table: cs
                        .lookup_table8
                        .iter()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None))
                        .collect(),
                    table_ids: cs.table_ids8.as_ref().map(|table_ids8| {
                        self.srs
                            .commit_evaluations_non_hiding(domain, table_ids8, None)
                    }),
                    max_joint_size: cs.configuration.lookup_info.max_joint_size,
                    runtime_tables_selector: cs
                        .runtime_selector
                        .as_ref()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None)),
                })
        };

        // TODO: Switch to commit_evaluations for all index polys
        VerifierIndex {
            domain,
            max_poly_size: self.max_poly_size,
            max_quot_size: self.max_quot_size,
            powers_of_alpha: self.powers_of_alpha.clone(),
            srs: {
                let cell = OnceCell::new();
                cell.set(Arc::clone(&self.srs)).unwrap();
                cell
            },

            public_input_size: self.cs.public,
            recursive_proofs: self.cs.recursive_proofs,
            recursive_log2_domain: math::ceil_log2(self.srs.max_degree()),

            sigma_comm: array_init(|i| self.srs.commit_non_hiding(&self.cs.sigmam[i], None)),
            coefficients_comm: array_init(|i| {
                self.srs
                    .commit_evaluations_non_hiding(domain, &self.cs.coefficients8[i], None)
            }),
            generic_comm: self.srs.commit_non_hiding(&self.cs.genericm, None),

            psm_comm: self.srs.commit_non_hiding(&self.cs.psm, None),

            complete_add_comm: self.srs.commit_evaluations_non_hiding(
                domain,
                &self.cs.complete_addl4,
                None,
            ),
            mul_comm: self
                .srs
                .commit_evaluations_non_hiding(domain, &self.cs.mull8, None),
            emul_comm: self
                .srs
                .commit_evaluations_non_hiding(domain, &self.cs.emull, None),

            endomul_scalar_comm: self.srs.commit_evaluations_non_hiding(
                domain,
                &self.cs.endomul_scalar8,
                None,
            ),

            chacha_comm: self.cs.chacha8.as_ref().map(|c| {
                array_init(|i| self.srs.commit_evaluations_non_hiding(domain, &c[i], None))
            }),

            range_check_comm: self
                .cs
                .range_check_selector_polys
                .iter()
                .map(|poly| {
                    self.srs
                        .commit_evaluations_non_hiding(domain, &poly.eval8, None)
                })
                .collect(),

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
            fr_sponge_params: self.cs.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
        }
    }
}

impl<G: CommitmentCurve> VerifierIndex<G>
where
    G::BaseField: PrimeField,
{
    ///
    // TODO: this is highly error-prone...
    pub fn absorb<EFqSponge>(&self, sponge: &mut EFqSponge)
    where
        EFqSponge: FqSponge<G::BaseField, G, G::ScalarField>,
    {
        // absorb all the commitments
        let commitments = self
            .sigma_comm
            .iter()
            .chain(&self.coefficients_comm)
            .chain([&self.generic_comm])
            .chain([&self.psm_comm])
            .chain([&self.complete_add_comm])
            .chain([&self.mul_comm])
            .chain([&self.emul_comm])
            .chain([&self.endomul_scalar_comm])
            .chain(self.chacha_comm.iter().flatten())
            .chain(&self.range_check_comm);

        for commitment in commitments {
            sponge.absorb_g(&commitment.unshifted);
        }

        // absorb all the lookup commitments
        if let Some(lcs) = &self.lookup_index {
            let commitments = lcs
                .lookup_table
                .iter()
                .chain(lcs.lookup_selectors.chacha.iter())
                .chain(lcs.lookup_selectors.chacha_final.iter())
                .chain(lcs.lookup_selectors.lookup_gate.iter())
                .chain(lcs.lookup_selectors.range_check_gate.iter())
                .chain(lcs.table_ids.iter())
                .chain(lcs.runtime_tables_selector.iter());

            for commitment in commitments {
                sponge.absorb_g(&commitment.unshifted);
            }
        }
    }

    /// Gets srs from [VerifierIndex] lazily
    pub fn srs(&self) -> &Arc<SRS<G>> {
        self.srs.get_or_init(|| {
            let mut srs = SRS::<G>::create(self.max_poly_size);
            srs.add_lagrange_basis(self.domain);
            Arc::new(srs)
        })
    }

    /// Gets zkpm from [VerifierIndex] lazily
    pub fn zkpm(&self) -> &DensePolynomial<G::ScalarField> {
        self.zkpm.get_or_init(|| zk_polynomial(self.domain))
    }

    /// Gets w from [VerifierIndex] lazily
    pub fn w(&self) -> &G::ScalarField {
        self.w.get_or_init(|| zk_w3(self.domain))
    }

    /// Deserializes a [VerifierIndex] from a file, given a pointer to an SRS and an optional offset in the file.
    pub fn from_file(
        srs: Option<Arc<SRS<G>>>,
        path: &Path,
        offset: Option<u64>,
        // TODO: we shouldn't have to pass these
        endo: G::ScalarField,
        fq_sponge_params: ArithmeticSpongeParams<G::BaseField>,
        fr_sponge_params: ArithmeticSpongeParams<G::ScalarField>,
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
        if srs.is_some() {
            verifier_index
                .srs
                .set(srs.unwrap())
                .map_err(|_| VerifierIndexError::SRSHasBeenSet.to_string())?;
        };

        verifier_index.endo = endo;
        verifier_index.fq_sponge_params = fq_sponge_params;
        verifier_index.fr_sponge_params = fr_sponge_params;

        Ok(verifier_index)
    }

    /// Writes a [VerifierIndex] to a file, potentially appending it to the already-existing content (if append is set to true)
    // TODO: append should be a bool, not an option
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
}
