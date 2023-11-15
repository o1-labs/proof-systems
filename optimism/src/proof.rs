use crate::circuits::expr::{ColumnEvaluations, ExprError};
use crate::mips::columns::{
    Column, FixedColumns, InstructionParts, InstructionSelectors, LookupCounters, NUM_LOOKUP_TERMS,
    SCRATCH_SIZE,
};
use crate::proof::PointEvaluations;
use ark_ec::AffineCurve;
use poly_commitment::{commitment::PolyComm, evaluation_proof::OpeningProof};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::array;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "G: ark_serialize::CanonicalDeserialize + ark_serialize::CanonicalSerialize")]
pub struct ProofCommitments<G: AffineCurve> {
    pub instruction_parts: InstructionParts<PolyComm<G>>,
    pub instruction_selectors: InstructionSelectors<PolyComm<G>>,
    pub initial_memory: Vec<PolyComm<G>>,
    pub final_memory: Vec<PolyComm<G>>,
    pub final_memory_write_index: Vec<PolyComm<G>>,
    pub initial_registers: PolyComm<G>,
    pub final_registers: PolyComm<G>,
    pub final_registers_write_index: PolyComm<G>,
    pub lookup_terms: [PolyComm<G>; NUM_LOOKUP_TERMS],
    pub lookup_aggregation: PolyComm<G>,
    pub instruction_pointer: PolyComm<G>,
    pub scratch_state: [PolyComm<G>; SCRATCH_SIZE],
    pub lookup_counters: LookupCounters<PolyComm<G>>,
    pub halt: PolyComm<G>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::SerializeAs<F>",
    deserialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::DeserializeAs<'de, F>"
))]
pub struct ProofEvaluations<F> {
    pub instruction_parts: InstructionParts<PointEvaluations<F>>,
    pub instruction_selectors: InstructionSelectors<PointEvaluations<F>>,
    pub fixed_columns: FixedColumns<PointEvaluations<F>>,
    pub initial_memory: Vec<PointEvaluations<F>>,
    pub final_memory: Vec<PointEvaluations<F>>,
    pub final_memory_write_index: Vec<PointEvaluations<F>>,
    pub initial_registers: PointEvaluations<F>,
    pub final_registers: PointEvaluations<F>,
    pub final_registers_write_index: PointEvaluations<F>,
    pub lookup_terms: [PointEvaluations<F>; NUM_LOOKUP_TERMS],
    pub lookup_aggregation: PointEvaluations<F>,
    pub instruction_pointer: PointEvaluations<F>,
    pub scratch_state: [PointEvaluations<F>; SCRATCH_SIZE],
    pub lookup_counters: LookupCounters<PointEvaluations<F>>,
    pub halt: PointEvaluations<F>,
}

impl<A: Clone> ProofEvaluations<A> {
    pub fn map<B, F: Fn(A) -> B>(self, f: F) -> ProofEvaluations<B> {
        let ProofEvaluations {
            instruction_parts,
            instruction_selectors,
            fixed_columns,
            initial_memory,
            final_memory,
            final_memory_write_index,
            initial_registers,
            final_registers,
            final_registers_write_index,
            lookup_terms,
            lookup_aggregation,
            instruction_pointer,
            scratch_state,
            lookup_counters,
            halt,
        } = self;
        let f = |x: PointEvaluations<A>| x.map(&f);
        ProofEvaluations {
            instruction_parts: instruction_parts.map(f),
            instruction_selectors: instruction_selectors.map(f),
            fixed_columns: fixed_columns.map(f),
            initial_memory: initial_memory.into_iter().map(f).collect(),
            final_memory: final_memory.into_iter().map(f).collect(),
            final_memory_write_index: final_memory_write_index.into_iter().map(f).collect(),
            initial_registers: f(initial_registers),
            final_registers: f(final_registers),
            final_registers_write_index: f(final_registers_write_index),
            lookup_terms: array::from_fn(|i| f(lookup_terms[i].clone())),
            lookup_aggregation: f(lookup_aggregation),
            instruction_pointer: f(instruction_pointer),
            scratch_state: array::from_fn(|i| f(scratch_state[i].clone())),
            lookup_counters: lookup_counters.map(f),
            halt: f(halt),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Proof<G: AffineCurve> {
    pub opening_proof: OpeningProof<G>,

    pub ft_eval1: G::ScalarField,

    pub t_comm: PolyComm<G>,

    pub commitments: ProofCommitments<G>,

    pub evaluations: ProofEvaluations<G::ScalarField>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::SerializeAs<Vec<G::ScalarField>>",
    deserialize = "Vec<o1_utils::serialization::SerdeAs>: serde_with::DeserializeAs<'de, Vec<G::ScalarField>>"
))]
pub struct SerializableProof<G: AffineCurve> {
    pub opening_proof: OpeningProof<G>,

    #[serde_as(as = "o1_utils::serialization::SerdeAs")]
    pub ft_eval1: G::ScalarField,

    pub t_comm: PolyComm<G>,

    pub commitments: ProofCommitments<G>,

    pub evaluations: ProofEvaluations<Vec<G::ScalarField>>,
}

impl<G: AffineCurve> Proof<G> {
    pub fn to_serializable(self) -> SerializableProof<G> {
        let Proof {
            opening_proof,
            ft_eval1,
            t_comm,
            commitments,
            evaluations,
        } = self;
        let f = |x: G::ScalarField| -> Vec<G::ScalarField> { vec![x] };
        SerializableProof {
            opening_proof,
            ft_eval1,
            t_comm,
            commitments,
            evaluations: evaluations.map(&f),
        }
    }
}

impl<G: AffineCurve> SerializableProof<G> {
    pub fn to_proof(self) -> Proof<G> {
        let SerializableProof {
            opening_proof,
            ft_eval1,
            t_comm,
            commitments,
            evaluations,
        } = self;
        let f = |x: Vec<_>| x[0];
        Proof {
            opening_proof,
            ft_eval1,
            t_comm,
            commitments,
            evaluations: evaluations.map(&f),
        }
    }
}

impl<F: Clone> ColumnEvaluations<F> for ProofEvaluations<F> {
    type Column = Column;
    fn evaluate(&self, col: Self::Column) -> Result<PointEvaluations<F>, ExprError<Self::Column>> {
        match col {
            Column::InstructionPart(instr_part) => Ok(self.instruction_parts[instr_part].clone()),
            Column::InstructionSelector(selector) => {
                Ok(self.instruction_selectors[selector].clone())
            }
            Column::FixedColumn(col) => Ok(self.fixed_columns[col].clone()),
            Column::InitialMemory(idx) => Ok(self.initial_memory[idx].clone()),
            Column::FinalMemory(idx) => Ok(self.final_memory[idx].clone()),
            Column::LookupTerm(idx) => Ok(self.lookup_terms[idx].clone()),
            Column::LookupAggregation => Ok(self.lookup_aggregation.clone()),
            Column::FinalMemoryWriteIndex(idx) => Ok(self.final_memory_write_index[idx].clone()),
            Column::InitialRegisters => Ok(self.initial_registers.clone()),
            Column::FinalRegisters => Ok(self.final_registers.clone()),
            Column::FinalRegistersWriteIndex => Ok(self.final_registers_write_index.clone()),
            Column::InstructionPointer => Ok(self.instruction_pointer.clone()),
            Column::ScratchState(idx) => Ok(self.scratch_state[idx].clone()),
            Column::LookupCounter(col) => Ok(self.lookup_counters[col].clone()),
            Column::Halt => Ok(self.halt.clone()),
        }
    }
}
