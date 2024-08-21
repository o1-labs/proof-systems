use mina_curves::pasta::Fp;
use sympolyc::expr::MVPoly;

#[test]
fn test_vector_space_dimension() {
    let p = MVPoly::<Fp, 2, 2>::new();
    assert_eq!(p.len(), 6);
    let p = MVPoly::<Fp, 3, 2>::new();
    assert_eq!(p.len(), 10);

    let p = MVPoly::<Fp, 1, 10>::new();
    assert_eq!(p.len(), 11);
}

#[test]
fn test_add() {
    let p1 = MVPoly::<Fp, 2, 2>::new();
    let p2 = MVPoly::<Fp, 2, 2>::new();
    let p3 = p1 + p2;
    assert_eq!(p3.len(), 6);
}
