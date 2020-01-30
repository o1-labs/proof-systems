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

    // TODO: Delete
    fn state(&self)  -> Vec<Fq>;

    fn digest(self) -> Fr;
}

