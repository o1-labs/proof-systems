use ark_ff::UniformRand;
use arrabbiata::{
    constraint,
    zkapp_registry::{minroot, ZkApp},
};
use mina_curves::pasta::{Fp, Vesta};

#[test]
fn test_minroot_number_of_constraints() {
    let mut env = constraint::Env::<Vesta>::new();
    let mut rng = o1_utils::tests::make_test_rng(None);

    let zkapp: minroot::MinRoot<Vesta> = minroot::MinRoot::<Vesta> {
        x: Fp::rand(&mut rng),
        y: Fp::rand(&mut rng),
        n: 10,
    };

    zkapp.run(&mut env, zkapp.fetch_instruction());
    let constraints = env.constraints;

    assert_eq!(constraints.len(), 4);
}
