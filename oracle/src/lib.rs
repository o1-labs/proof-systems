pub mod poseidon;
pub mod rndoracle;
pub mod bn_382;
pub mod marlin_sponge;

use algebra::Field;

pub trait FqSponge<Fq: Field, G, Fr> {
    fn new(p: poseidon::ArithmeticSpongeParams<Fq>) -> Self;
    fn absorb_g(&mut self, g: &G);
    fn absorb_fr(&mut self, x: &Fr);
    fn challenge(&mut self) -> Fr;
    fn challenge_fq(&mut self) -> Fq;

    fn digest(self) -> Fr;
}

