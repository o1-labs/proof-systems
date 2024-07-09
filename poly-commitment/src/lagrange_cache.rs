use std::{
    collections::hash_map::DefaultHasher,
    fs::{self, File},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use crate::{commitment::CommitmentCurve, PolyComm};
use ark_poly::Radix2EvaluationDomain as D;
use std::hash::{Hash, Hasher};

pub trait LagrangeCache<G: CommitmentCurve> {
    type CacheKey;

    fn lagrange_basis_cache_key(&self, g: &Vec<G>, domain: &D<G::ScalarField>) -> Self::CacheKey;

    fn load_lagrange_basis_from_cache(
        &self,
        g: &Vec<G>,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>>;

    fn cache_lagrange_basis(
        &self,
        g: &Vec<G>,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCache<G> {
    cache_dir: PathBuf,
    point_type: PhantomData<G>,
}

impl<G> FileCache<G> {
    pub fn new(cache_dir: PathBuf) -> Self {
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).unwrap();
        }
        FileCache {
            cache_dir,
            point_type: PhantomData,
        }
    }
}

impl<G> Default for FileCache<G> {
    fn default() -> Self {
        FileCache::new(PathBuf::from("/tmp/lagrange_cache"))
    }
}

impl<G: CommitmentCurve> LagrangeCache<G> for FileCache<G> {
    type CacheKey = PathBuf;

    fn lagrange_basis_cache_key(&self, g: &Vec<G>, domain: &D<G::ScalarField>) -> Self::CacheKey {
        let mut hasher = DefaultHasher::new();
        g.hash(&mut hasher);
        domain.size.hash(&mut hasher);
        self.cache_dir
            .clone()
            .join(format!("lagrange_basis_{:}", hasher.finish()))
    }

    fn load_lagrange_basis_from_cache(
        &self,
        g: &Vec<G>,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>> {
        let cache_key = self.lagrange_basis_cache_key(g, domain);
        if Path::exists(&cache_key) {
            let f = File::open(cache_key.clone()).expect(&format!(
                "Missing lagrange basis cache file {:?}",
                cache_key
            ));
            let basis = rmp_serde::decode::from_read(f).expect(&format!(
                "Error decoding lagrange cache file {:?}",
                cache_key
            ));
            Some(basis)
        } else {
            None
        }
    }

    fn cache_lagrange_basis(
        &self,
        g: &Vec<G>,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    ) {
        let cache_key = self.lagrange_basis_cache_key(g, domain);
        if Path::exists(&cache_key) {
            return;
        } else {
            let mut f = File::create(cache_key.clone()).expect(&format!(
                "Error creating lagrabnge basis cache file {:?}",
                cache_key
            ));
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

impl<G: CommitmentCurve> LagrangeCache<G> for GoogleCloudCache<G> {
    type CacheKey = ();

    fn lagrange_basis_cache_key(&self, g: &Vec<G>, domain: &D<G::ScalarField>) -> Self::CacheKey {
        todo!("GoogleCloudCache trait imp")
    }

    fn load_lagrange_basis_from_cache(
        &self,
        g: &Vec<G>,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>> {
        todo!("GoogleCloudCache trait impl")
    }

    fn cache_lagrange_basis(
        &self,
        g: &Vec<G>,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    ) {
        todo!("GoogleCloudCache trait impl")
    }
}
