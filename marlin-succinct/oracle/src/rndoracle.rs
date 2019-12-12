/*****************************************************************************************************************

This source file implements the random oracle argument API for Marlin.

*****************************************************************************************************************/

use std::fmt;
use algebra::{PairingEngine, PrimeField, ToBytes, BigInteger, to_bytes};
pub use super::poseidon::{ArithmeticSpongeParams, ArithmeticSponge, Sponge};

#[derive(Debug, Clone, Copy)]
pub enum ProofError
{
    WitnessCsInconsistent,
    PolyDivision,
    PolyCommit,
    PolyExponentiate,
    ProofCreation,
    ProofVerification,
    OpenProof,
    SumCheck,
    ConstraintInconsist,
    EvaluationGroup,
    OracleCommit
}

// Implement `Display` for ProofError
impl fmt::Display for ProofError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "({})", self)
    }
}

pub struct RandomOracleArgument<E: PairingEngine>
{
    sponge: ArithmeticSponge<E::Fr>,
    params: ArithmeticSpongeParams<E::Fr>,
}

impl<E: PairingEngine> RandomOracleArgument<E>
{
    pub fn new(params: ArithmeticSpongeParams<E::Fr>) -> Self
    {
        RandomOracleArgument::<E>
        {
            sponge: ArithmeticSponge::<E::Fr>::new(),
            params: params,
        }
    }

    pub fn commit_points(&mut self, points: &[E::G1Affine]) -> Result<bool, ProofError>
    {
        for point in points
        {
            let mut bytes: &[u8] = &to_bytes!(point).unwrap();
            let mut limbs = <E::Fr as PrimeField>::BigInt::default();
            let mut io_status = false;
            while bytes.len() > 0
            {
                match limbs.read_le(&mut bytes)
                {
                    // make sure at least one scalar is obtained from the point
                    Ok(_) => {io_status = true}
                    _ => {}
                }
            }
            if !io_status {return Err(ProofError::OracleCommit)}
            self.sponge.absorb(&self.params, &E::Fr::from_repr(limbs));
        }
        Ok(true)
    }

    pub fn commit_scalars(&mut self, scalars: &[E::Fr])
    {
        for scalar in scalars.iter()
        {
            self.sponge.absorb(&self.params, scalar);
        }
    }

    pub fn challenge(&mut self) -> E::Fr
    {
        self.sponge.squeeze(&self.params)
    }    
}
