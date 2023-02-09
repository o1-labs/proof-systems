use groupmap::{BWParameters, GroupMap};
use mina_curves::pasta::{vesta::Affine as Vesta, vesta::VestaConfig, Fq};

type G = VestaConfig;

#[test]
fn test_group_map_on_curve() {
    let params = BWParameters::<G>::setup();
    let t: Fq = rand::random();
    let (x, y) = BWParameters::<G>::to_group(&params, t);
    let g = Vesta::new(x, y);
    assert!(g.is_on_curve());
}

fn first_xy(xs: &[Fq; 3]) -> (Fq, Fq) {
    for x in xs.iter() {
        if let Some(y) = groupmap::get_y::<G>(*x) {
            return (*x, y);
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
        let g = Vesta::new(x, y);
        assert!(g.is_on_curve());
    }
}
