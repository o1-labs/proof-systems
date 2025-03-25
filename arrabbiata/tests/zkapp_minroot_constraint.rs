use ark_ff::UniformRand;
use arrabbiata::zkapp_registry::{get_constraints_per_gadget, setup, verifiable_minroot};
use mina_curves::pasta::{Fp, Vesta};

#[test]
fn test_minroot_number_of_constraints() {
    let mut rng = o1_utils::tests::make_test_rng(None);

    let zkapp: verifiable_minroot::MinRoot<Vesta> = {
        let x = Fp::rand(&mut rng);
        let y = Fp::rand(&mut rng);
        let n = 1000;
        verifiable_minroot::MinRoot::<Vesta>::new(x, y, n)
    };

    let circuit = setup(&zkapp);
    let constraints = get_constraints_per_gadget(&zkapp);
    assert_eq!(circuit.len(), 1000 + 196);
    // Number of gadgets
    assert_eq!(constraints.len(), 12 + 2 + 1);
}
