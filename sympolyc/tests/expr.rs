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

#[test]
pub fn test_normalized_indices() {
    let p = MVPoly::<Fp, 2, 2>::new();
    let indices = p.normalized_indices();
    assert_eq!(indices.len(), 6);
    assert_eq!(indices[0], 1);
    assert_eq!(indices[1], 2);
    assert_eq!(indices[2], 3);
    assert_eq!(indices[3], 4);
    assert_eq!(indices[4], 6);
    assert_eq!(indices[5], 9);

    let p = MVPoly::<Fp, 3, 2>::new();
    let indices = p.normalized_indices();
    assert_eq!(indices.len(), 10);
    assert_eq!(indices[0], 1);
    assert_eq!(indices[1], 2);
    assert_eq!(indices[2], 3);
    assert_eq!(indices[3], 4);
    assert_eq!(indices[4], 5);
    assert_eq!(indices[5], 6);
    assert_eq!(indices[6], 9);
    assert_eq!(indices[7], 10);
    assert_eq!(indices[8], 15);
    assert_eq!(indices[9], 25);
}
