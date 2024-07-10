use crate::{commitment::CommitmentCurve, PolyComm};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};
use std::hash::{Hash, Hasher};
use std::{
    collections::hash_map::DefaultHasher,
    fs::File,
    marker::PhantomData,
    path::{Path, PathBuf},
};

pub trait LagrangeCache {
    type CacheKey;

    fn lagrange_basis_cache_key<G: CommitmentCurve>(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
    ) -> Self::CacheKey;

    fn load_lagrange_basis_from_cache<G: CommitmentCurve>(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>>;

    fn cache_lagrange_basis<G: CommitmentCurve>(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCache {
    cache_dir: PathBuf,
}

impl FileCache {
    pub fn new(cache_dir: PathBuf) -> Self {
        FileCache { cache_dir }
    }
}

/*
The FileCache implementation uses a directory as a cache for the Lagrange basis hash map --
i.e every file corresponds to a Lagrange basis for a given G-basis and domain size.
*/
impl LagrangeCache for FileCache {
    type CacheKey = PathBuf;

    fn lagrange_basis_cache_key<G: CommitmentCurve>(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
    ) -> Self::CacheKey {
        let char = G::ScalarField::characteristic();
        let mut hasher = DefaultHasher::new();
        char.hash(&mut hasher);
        self.cache_dir.clone().join(format!(
            "lagrange_basis-{:}-{:}-{:}",
            hasher.finish(),
            srs_length,
            domain.size().to_string()
        ))
    }

    fn load_lagrange_basis_from_cache<G: CommitmentCurve>(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>> {
        let cache_key = self.lagrange_basis_cache_key::<G>(srs_length, domain);
        if Path::exists(&cache_key) {
            let f = File::open(cache_key.clone()).expect(&format!(
                "Missing lagrange basis cache file {:?}",
                cache_key
            ));
            let basis: Vec<PolyComm<G>> = rmp_serde::decode::from_read(f).expect(&format!(
                "Error decoding lagrange cache file {:?}",
                cache_key
            ));
            println!("Loaded lagrange basis from cache {:?}", cache_key);
            Some(basis)
        } else {
            println!("Missing lagrange basis cache file {:?}", cache_key);
            None
        }
    }

    fn cache_lagrange_basis<G: CommitmentCurve>(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    ) {
        let cache_key = self.lagrange_basis_cache_key::<G>(srs_length, domain);
        if Path::exists(&cache_key) {
            println!("Lagrange basis cache file {:?} already exists", cache_key);
            return;
        } else {
            let mut f = File::create(cache_key.clone()).expect(&format!(
                "Error creating lagrabnge basis cache file {:?}",
                cache_key
            ));
            println!("Caching lagrange basis to file {:?}", cache_key);
            rmp_serde::encode::write(&mut f, basis).expect(&format!(
                "Error encoding lagrange basis to file {:?}",
                cache_key
            ));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleCloudCache<G> {
    url: String,
    point_type: PhantomData<G>,
}

impl<G> GoogleCloudCache<G> {
    pub fn new(url: PathBuf) -> Self {
        todo!("GoogleCloudCache::new")
    }
}

/*
impl<G: CommitmentCurve> LagrangeCache<G> for GoogleCloudCache<G> {
    type CacheKey = ();

    fn lagrange_basis_cache_key(&self, domain: &D<G::ScalarField>) -> Self::CacheKey {
        todo!("GoogleCloudCache trait imp")
    }

    fn load_lagrange_basis_from_cache(
        &self,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>> {
        todo!("GoogleCloudCache trait impl")
    }

    fn cache_lagrange_basis(
        &self,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    ) {
        todo!("GoogleCloudCache trait impl")
    }
}
*/

pub mod test_caches {

    use once_cell::sync::Lazy;
    use std::{env, fs, path::PathBuf, str::FromStr};

    use super::FileCache;

    static LAGRANGE_CACHE_DIR: Lazy<PathBuf> = Lazy::new(|| {
        let base_dir = env::var("LAGRANGE_CACHE_DIR").unwrap_or("/tmp/lagrange_basis".to_string());
        let path = PathBuf::from_str(&base_dir).expect("Failed to create lagrange cache dir");
        if !path.exists() {
            println!("Creating base cache directory: {:?}", path);
            fs::create_dir_all(&path).unwrap();
        };
        path
    });

    pub fn get_file_cache() -> FileCache {
        super::FileCache::new(LAGRANGE_CACHE_DIR.clone())
    }
}
