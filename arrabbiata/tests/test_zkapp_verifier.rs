use arrabbiata::zkapp_registry::verifier::{Gadget, Verifier};
use core::marker::PhantomData;
use mina_curves::pasta::Vesta;

#[test]
fn test_zkapp_verifier_setup_size() {
    let zkapp: Verifier<Vesta> = Verifier::<Vesta> {
        _field: PhantomData,
    };
    let setup_size = arrabbiata::zkapp_registry::setup(&zkapp);

    // This is the current value of VERIFIER_CIRCUIT_SIZE in lib.rs
    assert_eq!(setup_size.len(), 196);
}

#[test]
fn test_zkapp_verifier_get_constraints_per_gadget() {
    let zkapp: Verifier<Vesta> = Verifier::<Vesta> {
        _field: PhantomData,
    };
    let constraints = arrabbiata::zkapp_registry::get_constraints_per_gadget(&zkapp);

    // Checking the number of gadgets
    // 12 for PoseidonFullRound
    // 1 for PoseidonAbsorb
    // 1 for NoOp
    assert_eq!(constraints.len(), 12 + 1 + 1);

    {
        let csts = constraints[&Gadget::PoseidonSpongeAbsorb].clone();
        assert_eq!(csts.len(), 2);
        // Each constraint has a degree of 1
        csts.iter().for_each(|c| {
            assert_eq!(c.degree(1, 0), 1);
        });
    }
    {
        (0..12).for_each(|i| {
            let csts = constraints[&Gadget::PoseidonFullRound(i * 5)].clone();
            assert_eq!(csts.len(), 15);
            // Each constraint has a degree of 5
            csts.iter().for_each(|c| {
                assert_eq!(c.degree(1, 0), 5);
            });
        });
    }

    {
        let csts = constraints[&Gadget::NoOp].clone();
        assert_eq!(csts.len(), 0);
    }
}
