//! Pasta multi-scalar multiplication through OpenVM's Weierstrass chips.
//!
//! The MSMs on the verification path are generic over `G: CommitmentCurve`, and
//! `CommitmentCurve` has a blanket impl for every `SWJAffine<P>` -- so there is
//! no per-curve override point, and Rust has no specialisation on stable. We
//! therefore dispatch on `TypeId` at runtime and fall back to arkworks for any
//! curve that is not Pasta.
//!
//! `TypeId` only *selects the branch*: the conversion goes through the generic
//! `to_coordinates()` / `of_coordinates()` pair and canonical byte encodings,
//! never a slice cast. This crate denies `unsafe_code` and there is exactly one
//! exception, on `try_msm`, because OpenVM marks its point constructor `unsafe`.
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
///
/// Reads the `[u64]` limbs via `BigInteger: AsRef<[u64]>` instead of
/// `to_bytes_le()`, which allocates a `Vec` per call -- ~130k heap allocations on
/// a 2^16 MSM, and the allocator is plain RISC-V in a zkVM. `.0` is unavailable:
/// `F::BigInt` is an associated type, not the concrete `BigInt<4>`.
fn le32<F: PrimeField>(x: &F) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bigint = x.into_bigint();
    let limbs = bigint.as_ref();
    // Bounded by `out`, not by the limb count: indexing `out[i*8..]` would panic
    // for a field wider than 4 limbs, and nothing in the signature restricts `F`.
    // Both Pasta fields are exactly 4 limbs, so nothing is dropped here; the
    // assert states that rather than leaving it to the reader.
    assert!(limbs.len() * 8 <= out.len(), "field wider than 32 bytes");
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
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
        // Branch before reading coordinates: the identity has no affine
        // representation, so `x()`/`y()` on it is unspecified rather than wrong.
        if acc.is_identity() {
            (true, ([0u8; 32], [0u8; 32]))
        } else {
            (false, le32_pair(&acc))
        }
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
/// # The `unsafe` exception, and why the checked constructor stays
///
/// OpenVM marks even its *checking* constructor `unsafe`, so the one
/// `#[allow(unsafe_code)]` in this crate lives here.
///
/// Do not replace `from_xy` with `from_xy_unchecked`. The bases arriving here are
/// a mix of provenances, and most of them are prover-controlled:
///
/// | source | trusted? |
/// |---|---|
/// | `srs.g`, `srs.h` | yes -- protocol constants |
/// | `opening.sg`, `opening.lr`, `opening.delta` | **no** -- from the proof |
/// | commitments via `combine_commitments` | **no** -- proof and verification key |
///
/// Those untrusted points *are* validated before reaching us -- `SerdeAs`
/// deserializes with `deserialize_compressed`, i.e. `Validate::Yes`, and
/// `SideLoadedVk::parse` checks the wrap-index commitments -- but that is a
/// property of code in two other crates. `from_xy` re-checks locally, so this
/// function stays correct even if either of those changes. An off-curve point
/// breaks the group law and opens twist attacks; at the cost of a few field
/// operations against a chip call, this is not a trade worth making.
///
/// Pasta curves have prime order (cofactor 1), so the curve-equation check is
/// *sufficient* -- no separate subgroup check is needed. Sufficient is not
/// optional: it remains mandatory on any untrusted point.
#[allow(unsafe_code)]
pub fn try_msm<G>(bases: &[G], scalars: &[G::ScalarField]) -> Option<G::Group>
where
    G: CommitmentCurve + 'static,
    G::BaseField: PrimeField,
{
    // A real assert, not `debug_assert`: this is a release build in the guest, and
    // `openvm_ecc_guest::msm` has unspecified behaviour on mismatched lengths. One
    // comparison against that is not a trade-off.
    assert_eq!(bases.len(), scalars.len(), "msm: base/scalar length mismatch");
    // Only the Pallas arm is reachable today: the sole caller is the wrap proof's
    // IPA verification, and the Vesta accumulator MSM goes through
    // `pickles_verifier::openvm_ec` instead. The Vesta arm is kept so a future
    // call site over Vesta is accelerated rather than silently falling back.
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
