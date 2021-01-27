pub mod poseidon;
pub mod poseidon_5_wires;
pub mod rndoracle;
pub mod pasta;
pub mod tweedle;
pub mod bn_382;
pub mod sponge;
pub mod sponge_5_wires;
pub mod utils;

use algebra::Field;

pub trait FqSponge<Fq: Field, G, Fr> {
    fn new(p: poseidon::ArithmeticSpongeParams<Fq>) -> Self;
    fn absorb_g(&mut self, g: &[G]);
    fn absorb_fr(&mut self, x: &[Fr]);
    fn challenge(&mut self) -> Fr;
    fn challenge_fq(&mut self) -> Fq;

    fn digest(self) -> Fr;
}
