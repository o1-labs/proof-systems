use ark_ec::AffineRepr;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use cache::LagrangeCache;
use mina_curves::pasta::{Pallas, Vesta};
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
use std::env;

pub trait WithLagrangeBasis<G: AffineRepr> {
    fn with_lagrange_basis(&self, domain: D<G::ScalarField>);
}

impl WithLagrangeBasis<Vesta> for SRS<Vesta> {
    fn with_lagrange_basis(&self, domain: D<<Vesta as AffineRepr>::ScalarField>) {
        match env::var("LAGRANGE_CACHE_DIR") {
            Ok(_) => add_lagrange_basis_with_cache(self, domain, cache::get_vesta_file_cache()),
            Err(_) => {
                self.get_lagrange_basis(domain);
            }
        }
    }
}

impl WithLagrangeBasis<Pallas> for SRS<Pallas> {
    fn with_lagrange_basis(&self, domain: D<<Pallas as AffineRepr>::ScalarField>) {
        match env::var("LAGRANGE_CACHE_DIR") {
            Ok(_) => add_lagrange_basis_with_cache(self, domain, cache::get_pallas_file_cache()),
            Err(_) => {
                self.get_lagrange_basis(domain);
            }
        }
    }
}

fn add_lagrange_basis_with_cache<G: CommitmentCurve, C: LagrangeCache<G>>(
    srs: &SRS<G>,
    domain: D<G::ScalarField>,
    cache: &C,
) {
    let n = domain.size();
    if srs.lagrange_bases.contains_key(&n) {
        return;
    }
    if let Some(basis) = cache.load_lagrange_basis_from_cache(srs.g.len(), &domain) {
        srs.lagrange_bases.get_or_generate(n, || basis);
    } else {
        let basis = srs.get_lagrange_basis(domain);
        cache.cache_lagrange_basis(srs.g.len(), &domain, basis);
    }
}

mod cache {
    use ark_ec::AffineRepr;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
    use core::marker::PhantomData;
    use mina_curves::pasta::{Pallas, Vesta};
    use once_cell::sync::Lazy;
    use poly_commitment::PolyComm;
    use std::{
        env, fs,
        fs::File,
        path::{Path, PathBuf},
    };

    pub trait LagrangeCache<G: AffineRepr> {
        type CacheKey;

        fn lagrange_basis_cache_key(
            &self,
            srs_length: usize,
            domain: &D<G::ScalarField>,
        ) -> Self::CacheKey;

        fn load_lagrange_basis_from_cache(
            &self,
            srs_length: usize,
            domain: &D<G::ScalarField>,
        ) -> Option<Vec<PolyComm<G>>>;

        fn cache_lagrange_basis(
            &self,
            srs_length: usize,
            domain: &D<G::ScalarField>,
            basis: &[PolyComm<G>],
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FileCache<G> {
        cache_dir: PathBuf,
        point_type: PhantomData<G>,
    }

    impl<G> FileCache<G> {
        fn new(cache_dir: PathBuf) -> Self {
            FileCache {
                cache_dir,
                point_type: PhantomData,
            }
        }
    }

    // The FileCache implementation uses a directory as a cache for the Lagrange
    // basis hash map -- i.e every file corresponds to a Lagrange basis for a
    // given G-basis and domain size.
    impl<G: AffineRepr> LagrangeCache<G> for FileCache<G> {
        type CacheKey = PathBuf;

        fn lagrange_basis_cache_key(
            &self,
            srs_length: usize,
            domain: &D<G::ScalarField>,
        ) -> Self::CacheKey {
            self.cache_dir.clone().join(format!(
                "lagrange_basis_{:}-{:}",
                srs_length,
                domain.size()
            ))
        }

        fn load_lagrange_basis_from_cache(
            &self,
            srs_length: usize,
            domain: &D<G::ScalarField>,
        ) -> Option<Vec<PolyComm<G>>> {
            let cache_key = self.lagrange_basis_cache_key(srs_length, domain);
            if Path::exists(&cache_key) {
                let f = File::open(cache_key.clone()).unwrap_or_else(|_| {
                    panic!("Missing lagrange basis cache file {:?}", cache_key)
                });
                let basis: Vec<PolyComm<G>> =
                    rmp_serde::decode::from_read(f).unwrap_or_else(|_| {
                        panic!("Error decoding lagrange cache file {:?}", cache_key)
                    });
                Some(basis)
            } else {
                None
            }
        }

        fn cache_lagrange_basis(
            &self,
            srs_length: usize,
            domain: &D<G::ScalarField>,
            basis: &[PolyComm<G>],
        ) {
            let cache_key = self.lagrange_basis_cache_key(srs_length, domain);
            if !Path::exists(&cache_key) {
                let mut f = File::create(cache_key.clone()).unwrap_or_else(|_| {
                    panic!("Error creating lagrange basis cache file {:?}", cache_key)
                });
                rmp_serde::encode::write(&mut f, basis).unwrap_or_else(|_| {
                    panic!("Error encoding lagrange basis to file {:?}", cache_key)
                });
            }
        }
    }

    // The following two caches are all that we need for mina tests. These will
    // not be initialized unless they are explicitly called.
    static VESTA_FILE_CACHE: Lazy<FileCache<Vesta>> = Lazy::new(|| {
        let cache_base_dir: String =
            env::var("LAGRANGE_CACHE_DIR").expect("LAGRANGE_CACHE_DIR missing in env");
        let cache_dir = PathBuf::from(format!("{}/vesta", cache_base_dir));
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).unwrap();
        }
        FileCache::new(cache_dir)
    });

    pub fn get_vesta_file_cache() -> &'static FileCache<Vesta> {
        &VESTA_FILE_CACHE
    }

    static PALLAS_FILE_CACHE: Lazy<FileCache<Pallas>> = Lazy::new(|| {
        let cache_base_dir: String =
            env::var("LAGRANGE_CACHE_DIR").expect("LAGRANGE_CACHE_DIR missing in env");
        let cache_dir = PathBuf::from(format!("{}/pallas", cache_base_dir));
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).unwrap();
        }
        FileCache::new(cache_dir)
    });

    pub fn get_pallas_file_cache() -> &'static FileCache<Pallas> {
        &PALLAS_FILE_CACHE
    }
}
