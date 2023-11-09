use ark_ff::PrimeField;
use kimchi::{
    circuits::{
        argument::Argument,
        expr,
        polynomials::{
            complete_add::CompleteAdd, endomul_scalar::EndomulScalar, endosclmul::EndosclMul,
            poseidon::Poseidon, varbasemul::VarbaseMul,
        },
    },
    curve::KimchiCurve,
    prover_index::ProverIndex,
};
use poly_commitment::{commitment::CommitmentCurve, evaluation_proof::OpeningProof};
use serde::Serialize;
use std::{
    collections::HashMap,
    fmt::Display,
    fs::{self, File},
    io::Write,
    path::Path,
};

pub struct StepInstance {}

pub struct StepWitness {}

pub struct WrapInstance {}

pub struct WrapWitness {}

pub fn prover() {}

pub fn verifier() {}
