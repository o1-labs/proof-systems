/*****************************************************************************************************************

This source file implements Plonk Protocol Index primitive.

*****************************************************************************************************************/

use crate::{
    alphas,
    circuits::{
        constraints::{zk_polynomial, zk_w3, ConstraintSystem},
        expr::{Linearization, PolishToken},
        gate::{LookupInfo, LookupsUsed},
        wires::*,
    },
    linearization::LinearizationAndAlphas,
};
use ark_ec::AffineCurve;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D};
use array_init::array_init;
use commitment_dlog::{
    commitment::{CommitmentCurve, PolyComm},
    srs::SRS,
    CommitmentField,
};
use once_cell::unsync::OnceCell;
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

type Fr<G> = <G as AffineCurve>::ScalarField;
type Fq<G> = <G as AffineCurve>::BaseField;

/// The index common to both the prover and verifier
// TODO: rename as ProverIndex
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Index<G: CommitmentCurve>
where
    G::ScalarField: CommitmentField,
{
    /// constraints system polynomials
    #[serde(bound = "ConstraintSystem<Fr<G>>: Serialize + DeserializeOwned")]
    pub cs: ConstraintSystem<Fr<G>>,

    /// The type of lookup used in the circuit. This is important to figure out what type of constraint we should include when building the polynomials for proofs (and proof verifications).
    pub lookup_used: Option<LookupsUsed>,

    /// The symbolic linearization of our circuit, which can compile to concrete types once certain values are learned in the protocol.
    /// Also contains the mapping to the powers of alpha
    #[serde(skip)]
    pub linearization_and_alphas: OnceCell<LinearizationAndAlphas<Fr<G>>>,

    /// polynomial commitment keys
    #[serde(skip)]
    pub srs: Arc<SRS<G>>,

    /// maximal size of polynomial section
    pub max_poly_size: usize,

    /// maximal size of the quotient polynomial according to the supported constraints
    pub max_quot_size: usize,

    /// random oracle argument parameters
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

/// The verifier index
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct VerifierIndex<G: CommitmentCurve> {
    /// evaluation domain
    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub domain: D<Fr<G>>,
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

    /// wire coordinate shifts
    #[serde_as(as = "[o1_utils::serialization::SerdeAs; PERMUTS]")]
    pub shift: [Fr<G>; PERMUTS],
    /// zero-knowledge polynomial
    #[serde(skip)]
    pub zkpm: DensePolynomial<Fr<G>>,
    // TODO(mimoo): isn't this redundant with domain.d1.group_gen ?
    /// domain offset for zero-knowledge
    #[serde(skip)]
    pub w: Fr<G>,
    /// endoscalar coefficient
    #[serde(skip)]
    pub endo: Fr<G>,

    pub lookup_used: Option<LookupsUsed>,
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_tables: Vec<Vec<PolyComm<G>>>,
    #[serde(bound = "PolyComm<G>: Serialize + DeserializeOwned")]
    pub lookup_selectors: Vec<PolyComm<G>>,

    /// linearization
    #[serde(skip)]
    linearization_and_alphas: OnceCell<LinearizationAndAlphas<Fr<G>>>,

    // random oracle argument parameters
    #[serde(skip)]
    pub fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
    #[serde(skip)]
    pub fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
}

impl<'a, G: CommitmentCurve> Index<G>
where
    G::BaseField: PrimeField,
    G::ScalarField: CommitmentField,
{
    /// Returns the [LinearizationAndAlphas] type associated with this circuit
    fn linearization_and_alphas(&self) -> &LinearizationAndAlphas<Fr<G>> {
        self.linearization_and_alphas.get_or_init(|| {
            let dummy_lookup_value = if self.lookup_used.is_some() {
                Some(&self.cs.dummy_lookup_values[0][..])
            } else {
                None
            };

            LinearizationAndAlphas::expr_linearization(
                self.cs.domain.d1,
                self.cs.chacha8.is_some(),
                dummy_lookup_value,
            )
        })
    }

    /// Returns the linearization
    pub fn linearization(&self) -> Linearization<Vec<PolishToken<Fr<G>>>> {
        self.linearization_and_alphas().linearization
    }

    /// Returns the mapping between constraints and their powers of alpha.
    pub fn powers_of_alpha(&self) -> alphas::Builder {
        self.linearization_and_alphas().powers_of_alpha
    }

    pub fn verifier_index(&self) -> VerifierIndex<G> {
        let domain = self.cs.domain.d1;
        let linearization_and_alphas = if let Some(x) = self.linearization_and_alphas.get() {
            let cell: OnceCell<LinearizationAndAlphas<Fr<G>>> = OnceCell::new();
            cell.set(x.clone());
            cell
        } else {
            OnceCell::new()
        };

        // TODO: Switch to commit_evaluations for all index polys
        VerifierIndex {
            domain,
            max_poly_size: self.max_poly_size,
            max_quot_size: self.max_quot_size,
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

            shift: self.cs.shift,
            zkpm: self.cs.zkpm.clone(),
            w: zk_w3(self.cs.domain.d1),
            endo: self.cs.endo,

            lookup_used: self.lookup_used,
            lookup_tables: self
                .cs
                .lookup_tables8
                .iter()
                .map(|v| {
                    v.iter()
                        .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None))
                        .collect()
                })
                .collect(),
            lookup_selectors: self
                .cs
                .lookup_selectors
                .iter()
                .map(|e| self.srs.commit_evaluations_non_hiding(domain, e, None))
                .collect(),

            linearization_and_alphas,

            fr_sponge_params: self.cs.fr_sponge_params.clone(),
            fq_sponge_params: self.fq_sponge_params.clone(),
        }
    }

    // this function compiles the index from constraints
    pub fn create(
        mut cs: ConstraintSystem<Fr<G>>,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        endo_q: Fr<G>,
        srs: Arc<SRS<G>>,
    ) -> Self {
        let max_poly_size = srs.g.len();
        if cs.public > 0 {
            assert!(
                max_poly_size >= cs.domain.d1.size as usize,
                "polynomial segment size has to be not smaller that that of the circuit!"
            );
        }
        cs.endo = endo_q;

        let lookup_info = LookupInfo::<Fr<G>>::create();
        let lookup_used = lookup_info.lookup_used(&cs.gates);
        let linearization_and_alphas = OnceCell::new();
        let max_quot_size = PERMUTS * cs.domain.d1.size as usize;

        Index {
            cs,
            lookup_used,
            linearization_and_alphas,
            srs,
            max_poly_size,
            max_quot_size,
            fq_sponge_params,
        }
    }
}

impl<G> VerifierIndex<G>
where
    G: CommitmentCurve,
{
    /// Returns the [LinearizationAndAlphas] type associated with this circuit
    pub fn linearization_and_powers_of_alpha(&self) -> &LinearizationAndAlphas<Fr<G>> {
        self.linearization_and_alphas.get_or_init(|| {
            let dummy_lookup_value = if self.lookup_used.is_some() {
                Some(&self.cs.dummy_lookup_values[0][..])
            } else {
                None
            };

            LinearizationAndAlphas::expr_linearization(
                self.cs.domain.d1,
                self.cs.chacha8.is_some(),
                dummy_lookup_value,
            )
        })
    }

    /// Returns the linearization
    pub fn linearization(&self) -> Linearization<Vec<PolishToken<Fr<G>>>> {
        self.linearization_and_powers_of_alpha().linearization
    }

    /// Returns the mapping between constraints and their powers of alpha.
    pub fn powers_of_alpha(&self) -> alphas::Builder {
        self.linearization_and_powers_of_alpha().powers_of_alpha
    }

    /// Deserializes a [VerifierIndex] from a file, given a pointer to an SRS and an optional offset in the file.
    pub fn from_file(
        srs: Arc<SRS<G>>,
        path: &Path,
        offset: Option<u64>,
        // TODO: we shouldn't have to pass these
        endo: G::ScalarField,
        fq_sponge_params: ArithmeticSpongeParams<Fq<G>>,
        fr_sponge_params: ArithmeticSpongeParams<Fr<G>>,
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
        verifier_index.srs = srs;
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
