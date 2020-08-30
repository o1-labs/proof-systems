use algebra::{bn_382::g::Affine };
use commitment_dlog::srs::SRS;

#[test]
fn srs_inclusion() {
    let size = 100;
    let n = 5;

    let srss : Vec<_> = (0..n).map(|i| SRS::<Affine>::create(size * (i + 1), 0, 0)).collect();

    for i in 0..(srss.len() - 1) {
        assert!(srss[i].g.iter().zip(srss[i + 1].g.iter()).all(|(g1, g2)| g1 == g2));
        assert!(srss[i].h == srss[i + 1].h);
    }
}
