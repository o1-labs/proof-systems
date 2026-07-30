//! Pasta multi-scalar multiplication through OpenVM's Weierstrass chips.
//!
//! The MSMs on the verification path are generic over `G: CommitmentCurve`, and
//! `CommitmentCurve` has a blanket impl for every `SWJAffine<P>` -- so there is
//! no per-curve override point, and Rust has no specialisation on stable. We
//! therefore dispatch on `TypeId` at runtime and fall back to arkworks for any
//! curve that is not Pasta.
//!
//! No `unsafe`, which this crate forbids: `TypeId` only *selects the branch*.
//! The conversion itself goes through the generic `to_coordinates()` /
//! `of_coordinates()` pair and canonical byte encodings, never a slice cast.
//!
//! Points are rebuilt with the *checked* `from_xy`, which verifies the affine
//! curve equation. That is deliberate: OpenVM's docs warn that
//! *"Deserializing these points does not check that they are on the curve"*, and
//! the checked constructor costs one field operation against a chip call.

use alloc::vec::Vec;
use core::any::TypeId;

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, Zero};
use mina_curves::pasta::{
    OpenVmFpMod, OpenVmFqMod, OpenVmPallas, OpenVmVesta, Pallas, Vesta,
};
use openvm_algebra_guest::IntMod;
use openvm_ecc_guest::{weierstrass::WeierstrassPoint, Group};

use crate::commitment::CommitmentCurve;

/// Canonical little-endian 32 bytes. This is where arkworks' Montgomery form is
/// reduced to the canonical representation the chip expects.
fn le32<F: PrimeField>(x: &F) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_le();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

macro_rules! chip_msm {
    ($bases:expr, $scalars:expr, $Point:ty, $Coord:ty, $Scalar:ty) => {{
        let mut pts: Vec<$Point> = Vec::with_capacity($bases.len());
        for b in $bases {
            match b.to_coordinates() {
                // arkworks reports the identity as "no coordinates".
                None => pts.push(<$Point as Group>::IDENTITY),
                Some((x, y)) => {
                    let px = <$Coord>::from_le_bytes_unchecked(&le32(&x));
                    let py = <$Coord>::from_le_bytes_unchecked(&le32(&y));
                    // Checked constructor: validates the affine curve equation.
                    // See the `allow(unsafe_code)` justification on `try_msm`.
                    let pt = unsafe { <$Point>::from_xy(px, py) }
                        .expect("arkworks point not on curve");
                    pts.push(pt);
                }
            }
        }
        let coeffs: Vec<$Scalar> = $scalars
            .iter()
            .map(|s| <$Scalar>::from_le_bytes_unchecked(&le32(s)))
            .collect();
        let acc = openvm_ecc_guest::msm(&coeffs, &pts);
        (acc.is_identity(), le32_pair(&acc))
    }};
}

/// Extract an accumulated point's coordinates as canonical bytes.
fn le32_pair<P: WeierstrassPoint>(p: &P) -> ([u8; 32], [u8; 32])
where
    P::Coordinate: IntMod,
{
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&p.x().as_le_bytes()[..32]);
    y.copy_from_slice(&p.y().as_le_bytes()[..32]);
    (x, y)
}

/// `Σ scalars[i] · bases[i]` via the chip, or `None` if `G` is not Pasta.
///
/// Callers keep their arkworks path as the fallback, so a non-Pasta curve --
/// or a host build -- behaves exactly as before.
///
/// # The `unsafe` exception
///
/// This crate denies `unsafe_code` and we keep it that way everywhere else. The
/// exception is confined to the point construction below, because OpenVM marks
/// even its *checking* constructor `unsafe`: `from_xy` validates the affine curve
/// equation but not subgroup membership, so the API leaves that to the caller.
/// Our bases are arkworks points, already on the curve and in the prime-order
/// subgroup, so the obligation is discharged -- and we still call the checking
/// variant rather than `from_xy_unchecked`, so a violated assumption fails loudly
/// instead of silently yielding a wrong point.
#[allow(unsafe_code)]
pub fn try_msm<G>(bases: &[G], scalars: &[G::ScalarField]) -> Option<G::Group>
where
    G: CommitmentCurve + 'static,
    G::BaseField: PrimeField,
{
    debug_assert_eq!(bases.len(), scalars.len());
    let (is_id, (x, y)) = if TypeId::of::<G>() == TypeId::of::<Vesta>() {
        chip_msm!(bases, scalars, OpenVmVesta, OpenVmFqMod, OpenVmFpMod)
    } else if TypeId::of::<G>() == TypeId::of::<Pallas>() {
        chip_msm!(bases, scalars, OpenVmPallas, OpenVmFpMod, OpenVmFqMod)
    } else {
        return None;
    };

    if is_id {
        return Some(G::Group::zero());
    }
    let gx = G::BaseField::from_le_bytes_mod_order(&x);
    let gy = G::BaseField::from_le_bytes_mod_order(&y);
    Some(G::of_coordinates(gx, gy).into_group())
}
