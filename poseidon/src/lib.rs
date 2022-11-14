pub mod constants;
pub mod pasta;
pub mod permutation;
pub mod poseidon;
pub mod sponge;

#[cfg(test)]
mod tests;

use ark_ff::Field;

pub trait FqSponge<Fq: Field, G, Fr> {
    fn new(p: &'static poseidon::ArithmeticSpongeParams<Fq>) -> Self;
    fn absorb_g(&mut self, g: &[G]);
    fn absorb_fq(&mut self, x: &[Fq]);
    fn absorb_fr(&mut self, x: &[Fr]);
    fn challenge(&mut self) -> Fr;
    fn challenge_fq(&mut self) -> Fq;

    fn digest(self) -> Fr;
    fn digest_fq(self) -> Fq;
}
