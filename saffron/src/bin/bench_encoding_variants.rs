use std::time::Instant;

use kimchi::circuits::domains::EvaluationDomains;
use mina_curves::pasta::{Fp, Vesta};
use poly_commitment::{ipa::SRS, SRS as _};
use saffron::encoding::{commit, sparse::SparseState};

pub fn main() {
    // Sparse state
    let sparse_state = SparseState {
        bytes: vec![1; 1000],
    };
    let srs_size = 1 << 16;
    let domain_fp = EvaluationDomains::<Fp>::create(srs_size).unwrap();
    let srs_e1: SRS<Vesta> = {
        let start = Instant::now();
        let srs = SRS::create(srs_size);
        println!("SRS for E1 created in {:?}", start.elapsed());
        let start = Instant::now();
        srs.get_lagrange_basis(domain_fp.d1);
        println!("Lagrange basis for E1 added in {:?}", start.elapsed());
        srs
    };

    let _ = commit(sparse_state, srs_e1.clone(), domain_fp.d1);

    let sparse_state = SparseState {
        bytes: vec![1; (1 << 16) + 1],
    };

    let _ = commit(sparse_state, srs_e1, domain_fp.d1);
}
