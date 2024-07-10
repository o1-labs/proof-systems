use std::{
    fs::File,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use crate::{commitment::CommitmentCurve, PolyComm};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain as D};

pub trait LagrangeCache<G: CommitmentCurve> {
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
        FileCache {
            cache_dir,
            point_type: PhantomData,
        }
    }
}

/*
The FileCache implementation uses a directory as a cache for the Lagrange basis hash map --
i.e every file corresponds to a Lagrange basis for a given G-basis and domain size.
*/
impl<G: CommitmentCurve> LagrangeCache<G> for FileCache<G> {
    type CacheKey = PathBuf;

    fn lagrange_basis_cache_key(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
    ) -> Self::CacheKey {
        self.cache_dir.clone().join(format!(
            "lagrange_basis_{:}-{:}",
            srs_length,
            domain.size().to_string()
        ))
    }

    fn load_lagrange_basis_from_cache(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
    ) -> Option<Vec<PolyComm<G>>> {
        let cache_key = self.lagrange_basis_cache_key(srs_length, domain);
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

    fn cache_lagrange_basis(
        &self,
        srs_length: usize,
        domain: &D<G::ScalarField>,
        basis: &Vec<PolyComm<G>>,
    ) {
        let cache_key = self.lagrange_basis_cache_key(srs_length, domain);
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

#[cfg(test)]
pub mod test_caches {
    use super::FileCache;
    use mina_curves::pasta::Vesta;
    use once_cell::sync::Lazy;
    use std::{fs, path::PathBuf, str::FromStr};

    static VESTA_FILE_CACHE: Lazy<FileCache<Vesta>> = Lazy::new(|| {
        let cache_dir = PathBuf::from_str("/tmp/lagrange_basis/vesta")
            .expect("Failed to create bn254 lagrange cache");
        if !cache_dir.exists() {
            println!("Creating cache directory: {:?}", cache_dir);
            fs::create_dir_all(&cache_dir).unwrap();
        }
        FileCache::new(cache_dir)
    });

    pub fn get_vesta_file_cache() -> &'static FileCache<Vesta> {
        &*VESTA_FILE_CACHE
    }

    static BN254_FILE_CACHE: Lazy<FileCache<ark_bn254::G1Affine>> = Lazy::new(|| {
        let cache_dir = PathBuf::from_str("/tmp/lagrange_basis/bn254")
            .expect("Failed to create bn254 lagrange cache");
        if !cache_dir.exists() {
            println!("Creating cache directory: {:?}", cache_dir);
            fs::create_dir_all(&cache_dir).unwrap();
        }
        FileCache::new(cache_dir)
    });

    pub fn get_bn254_file_cache() -> &'static FileCache<ark_bn254::G1Affine> {
        &*BN254_FILE_CACHE
    }
}
