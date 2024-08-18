use mina_curves::pasta::Fp;
use sympolyc::expr::MVPoly;

#[test]
fn test_vector_space_dimension() {
    let p = MVPoly::<Fp, 2, 2>::new();
    assert_eq!(p.coeff.len(), 6);
    let p = MVPoly::<Fp, 3, 2>::new();
    assert_eq!(p.coeff.len(), 10);

    let p = MVPoly::<Fp, 1, 10>::new();
    assert_eq!(p.coeff.len(), 11);
}
