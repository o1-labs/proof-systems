pub trait SpongeConstants {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize;
    const PERM_ROUNDS_PARTIAL: usize;
    const PERM_HALF_ROUNDS_FULL: usize;
    const PERM_SBOX: u32;
    const PERM_FULL_MDS: bool;
    const PERM_INITIAL_ARK: bool;
}

#[derive(Clone)]
pub struct PlonkSpongeConstantsLegacy {}

impl SpongeConstants for PlonkSpongeConstantsLegacy {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = 63;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 5;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = true;
}

#[derive(Clone)]
pub struct PlonkSpongeConstantsKimchi {}

impl SpongeConstants for PlonkSpongeConstantsKimchi {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = 55;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 7;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = false;
}

/// Constants used by the IVC circuit used by the folding scheme
/// This is meant to be only used for the IVC circuit, with the BN254 curve
/// It has not been tested with/for other curves
#[derive(Clone)]
pub struct PlonkSpongeConstantsIVC {}

impl SpongeConstants for PlonkSpongeConstantsIVC {
    const SPONGE_CAPACITY: usize = 1;
    const SPONGE_WIDTH: usize = 3;
    const SPONGE_RATE: usize = 2;
    const PERM_ROUNDS_FULL: usize = 55;
    const PERM_ROUNDS_PARTIAL: usize = 0;
    const PERM_HALF_ROUNDS_FULL: usize = 0;
    const PERM_SBOX: u32 = 7;
    const PERM_FULL_MDS: bool = true;
    const PERM_INITIAL_ARK: bool = false;
}
