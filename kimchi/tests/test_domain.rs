use ark_ff::Field;
use kimchi::circuits::domains::EvaluationDomains;
use mina_curves::pasta::Fp;

#[test]
fn test_create_domain() {
    if let Ok(d) = EvaluationDomains::<Fp>::create(usize::MAX) {
        assert!(d.d4.group_gen.pow([4]) == d.d1.group_gen);
        assert!(d.d8.group_gen.pow([2]) == d.d4.group_gen);
        println!("d8 = {:?}", d.d8.group_gen);
        println!("d8^2 = {:?}", d.d8.group_gen.pow([2]));
        println!("d4 = {:?}", d.d4.group_gen);
        println!("d4 = {:?}", d.d4.group_gen.pow([4]));
        println!("d1 = {:?}", d.d1.group_gen);
    }
}
