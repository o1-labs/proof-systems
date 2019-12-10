/*****************************************************************************************************************

This source file implements the random oracle argument API for Marlin.

*****************************************************************************************************************/

use std::fmt;
use algebra::Field;
pub use super::poseidon::{ArithmeticSpongeParams, ArithmeticSponge, Sponge};

#[derive(Debug, Clone, Copy)]
pub enum ProofError
{
    WitnessCsInconsistent,
    PolyDivision,
    ProofCreation,
    ProofVerification,
    OpenProof,
    SumCheck,
}

// Implement `Display` for ProofError
impl fmt::Display for ProofError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "({})", self)
    }
}

pub struct RandomOracleArgument<F: Field>
{
    sponge: ArithmeticSponge<F>,
    params: ArithmeticSpongeParams<F>,
}

impl<F: Field> RandomOracleArgument<F>
{
    pub fn new(params: ArithmeticSpongeParams<F>) -> Self
    {
        RandomOracleArgument::<F>
        {
            sponge: ArithmeticSponge::<F>::new(),
            params: params,
        }
    }

    pub fn commit_scalar(&mut self, scalar: &F)
    {
        self.sponge.absorb(&self.params, scalar);
    }

    pub fn commit_slice(&mut self, slice: &[F])
    {
        for x in slice.iter()
        {
            self.sponge.absorb(&self.params, x);
        }
    }

    pub fn challenge(&mut self) -> F
    {
        self.sponge.squeeze(&self.params)
    }    
}
