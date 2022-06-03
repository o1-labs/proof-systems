//! This module implements the verifier index as [VerifierIndex].
//! You can derive this struct from the [ProverIndex] struct.

use crate::alphas::Alphas;
use crate::circuits::lookup::lookups::LookupsUsed;
use crate::circuits::polynomials::permutation::zk_polynomial;
use crate::circuits::polynomials::permutation::zk_w3;
use crate::circuits::{
    expr::{Linearization, PolishToken},
    wires::*,
};
use crate::prover_index::ProverIndex;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use array_init::array_init;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::SRS,
};
use o1_utils::types::fields::*;
use oracle::poseidon::ArithmeticSpongeParams;
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
    pub lookup_selectors: Vec<PolyComm<G>>,

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
    pub domain: D<ScalarField<G>>,
    /// maximal size of polynomial section
    pub max_poly_size: usize,
    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,
    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: Arc<SRS<G>>,

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
    pub shift: [ScalarField<G>; PERMUTS],
    /// zero-knowledge polynomial
    #[serde(skip)]
    pub zkpm: DensePolynomial<ScalarField<G>>,
    // TODO(mimoo): isn't this redundant with domain.d1.group_gen ?
    /// domain offset for zero-knowledge
    #[serde(skip)]
    pub w: ScalarField<G>,
    /// endoscalar coefficient
    #[serde(skip)]
    pub endo: ScalarField<G>,

    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_index: Option<LookupVerifierIndex<G>>,

    #[serde(skip)]
    pub linearization: Linearization<Vec<PolishToken<ScalarField<G>>>>,
    /// The mapping between powers of alpha and constraints
    #[serde(skip)]
    pub powers_of_alpha: Alphas<ScalarField<G>>,

    // random oracle argument parameters
    #[serde(skip)]
    pub fr_sponge_params: ArithmeticSpongeParams<ScalarField<G>>,
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<BaseField<G>>,
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
                        .iter()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None))
                        .collect(),
                    lookup_table: cs
                        .lookup_table8
                        .iter()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None))
                        .collect(),
                    table_ids: cs.table_ids8.as_ref().map(|table_ids8| {
                        self.srs
                            .commit_evaluations_non_hiding(domain, table_ids8, None)
                    }),
                    max_joint_size: cs.configuration.max_joint_size,
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
            srs: Arc::clone(&self.srs),

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
            zkpm: self.cs.precomputations().zkpm.clone(),
            w: zk_w3(self.cs.domain.d1),
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
    /// Deserializes a [VerifierIndex] from a file, given a pointer to an SRS and an optional offset in the file.
    pub fn from_file(
        srs: Option<Arc<SRS<G>>>,
        path: &Path,
        offset: Option<u64>,
        // TODO: we shouldn't have to pass these
        endo: G::ScalarField,
        fq_sponge_params: ArithmeticSpongeParams<BaseField<G>>,
        fr_sponge_params: ArithmeticSpongeParams<ScalarField<G>>,
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
        verifier_index.srs = srs.unwrap_or_else(|| {
            let mut srs = SRS::<G>::create(verifier_index.max_poly_size);
            srs.add_lagrange_basis(verifier_index.domain);
            Arc::new(srs)
        });

        verifier_index.endo = endo;
        verifier_index.fq_sponge_params = fq_sponge_params;
        verifier_index.fr_sponge_params = fr_sponge_params;
        verifier_index.w = zk_w3(verifier_index.domain);
        verifier_index.zkpm = zk_polynomial(verifier_index.domain);

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
