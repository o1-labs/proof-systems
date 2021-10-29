use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::{
    vesta::{Affine, VestaParameters},
    Fq,
};

type G = VestaParameters;

#[test]
fn test_group_map_on_curve() {
    let params = BWParameters::<G>::setup();
    let t: Fq = rand::random();
    let (x, y) = BWParameters::<G>::to_group(&params, t);
    let g = Affine::new(x, y, false);
    assert!(g.is_on_curve());
}

fn first_xy(xs: &[Fq; 3]) -> (Fq, Fq) {
    for x in xs.iter() {
        match groupmap::get_y::<G>(*x) {
            Some(y) => return (*x, y),
            None => (),
        }
    }
    panic!("get_xy")
}

#[test]
fn test_batch_group_map_on_curve() {
    let params = BWParameters::<G>::setup();
    let ts: Vec<Fq> = (0..1000).map(|_| rand::random()).collect();
    for xs in BWParameters::<G>::batch_to_group_x(&params, ts).iter() {
        let (x, y) = first_xy(xs);
        let g = Affine::new(x, y, false);
        assert!(g.is_on_curve());
    }
}
