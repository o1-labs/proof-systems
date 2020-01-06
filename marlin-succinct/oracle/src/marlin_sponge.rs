use algebra::{Field, PrimeField, PairingEngine};
use crate::poseidon::{ArithmeticSpongeParams, ArithmeticSponge, Sponge};

pub trait FqSponge<Fq: Field, G, Fr> {
    fn new(p : ArithmeticSpongeParams<Fq>) -> Self;
    fn absorb_g(&mut self, g : &G);
    fn absorb_fr(&mut self, x : &Fr);
    fn challenge(&mut self) -> Fr;

    fn digest(self) -> Fr;
}

pub trait FrSponge<Fr: Field> {
    fn new(p : ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x : &Fr);
    fn challenge(&mut self) -> Fr;
    fn absorb_evaluations(&mut self, e : &ProofEvaluations<Fr>);
}

pub trait SpongePairingEngine : PairingEngine {
    type FqSponge : FqSponge<Self::Fq, Self::G1Affine, Self::Fr>;
    type FrSponge : FrSponge<Self::Fr>;
}
