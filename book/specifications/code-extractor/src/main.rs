use kimchi::{
    circuits::{gate::CircuitGate, wires::Wire},
    index::{expr_linearization, testing::new_index_for_test},
};
use mina_curves::pasta::fp::Fp;

fn main() {
    let gates = vec![CircuitGate::<Fp>::zero(Wire::new(0)); 2];
    let index = new_index_for_test(gates, 0);
    let (_linearization, powers_of_alpha) = expr_linearization(
        index.cs.domain.d1,
        index.cs.chacha8.is_some(),
        &index.cs.lookup_constraint_system,
    );
    println!("{}", powers_of_alpha);
}
