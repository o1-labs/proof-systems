//! Windowed Pippenger with a window sized for the MSMs this verifier actually
//! runs.
//!
//! `openvm_ecc_guest::msm` is a software Pippenger whose inner `Add` is the
//! chip intrinsic — the win there is per point-addition, not algorithmic. Its
//! window is `c = bases.len().ilog2()`, i.e. **16** for the `2^16`-point
//! accumulator MSM, which is far past the optimum: the bucket pass costs
//! `2^c` additions per window and overtakes the `n` additions it is meant to
//! save.
//!
//! Point additions for `n = 65536`, 256-bit scalars:
//!
//! | window | windows | point ops | bucket memory |
//! |---|---|---|---|
//! | upstream, `c = 16` (Booth) | 17 | 2.23M | 2 MiB |
//! | `c = 12` (here) | 22 | 1.62M | 256 KiB |
//!
//! ×1.38 on the operation count, and 8× less bucket memory — which is worth
//! more than it looks in a zkVM, where every access crosses the memory chip.
//!
//! This is plain unsigned Pippenger, not upstream's Booth-encoded variant.
//! Booth would halve the bucket count again (~1.62M → 1.48M, another ~9%), but
//! it earns that with a signed-digit encoding that is easy to get subtly wrong;
//! the window size is where the factor is.
//!
//! # Soundness
//!
//! A wrong result here cannot forge anything. Both call sites *compare* the
//! output against a value the proof supplied — the accumulator check and the
//! IPA equation — so a bug yields a rejection, never an acceptance. That is the
//! same argument that covers the chip itself: it produces a point, it decides
//! nothing.

use alloc::{vec, vec::Vec};
use core::ops::Add;

use openvm_algebra_guest::IntMod;
use openvm_ecc_guest::Group;

/// Window size minimising `ceil(256/c) * (n + 2*(2^c - 1))`, the additions a
/// window pass costs: `n` to fill the buckets, and two per bucket for the
/// running-sum readout.
///
/// Computed rather than tabulated because both MSMs on the path have different
/// sizes (`2^16` for the accumulator, `2^13..2^15` for the wrap IPA) and the
/// optimum moves with `n`.
fn best_window(n: usize, scalar_bits: usize) -> usize {
    let cost = |c: usize| -> u64 {
        let windows = scalar_bits.div_ceil(c) as u64;
        let buckets = 2u64 * ((1u64 << c) - 1);
        windows * (n as u64 + buckets)
    };
    // 1..=16: below 1 there is no window, and past 16 the bucket pass dominates
    // for any n this verifier sees.
    (1..=16).min_by_key(|&c| cost(c)).expect("non-empty range")
}

/// Bits `[w*c, w*c + c)` of a little-endian scalar, as a bucket index.
///
/// Reads four bytes covering the window and shifts: `c <= 16` and the shift is
/// at most 7, so 23 bits are needed and a `u32` is always enough.
#[inline]
fn window_at(bytes: &[u8], w: usize, c: usize) -> usize {
    let bit = w * c;
    let byte = bit / 8;
    let shift = bit % 8;
    let mut buf = [0u8; 4];
    for (dst, src) in buf.iter_mut().zip(bytes.iter().skip(byte)) {
        *dst = *src;
    }
    let v = u32::from_le_bytes(buf) >> shift;
    (v & ((1u32 << c) - 1)) as usize
}

/// `Σ coeffs[i] · bases[i]`.
///
/// Mirrors `openvm_ecc_guest::msm`'s contract, including that the caller passes
/// equal-length slices.
pub fn msm<P, S>(coeffs: &[S], bases: &[P]) -> P
where
    P: Group,
    for<'a> &'a P: Add<&'a P, Output = P>,
    S: IntMod,
{
    assert_eq!(
        coeffs.len(),
        bases.len(),
        "msm requires matching scalar/base lengths"
    );
    if bases.is_empty() {
        return P::IDENTITY;
    }

    let scalar_bits = S::NUM_LIMBS * 8;
    let c = best_window(bases.len(), scalar_bits);
    let windows = scalar_bits.div_ceil(c);
    // Bucket 0 is never used -- a zero window contributes nothing -- so index
    // `k` lives at `k - 1` and the vector is one shorter.
    let n_buckets = (1usize << c) - 1;

    let scalars: Vec<&[u8]> = coeffs.iter().map(|s| s.as_le_bytes()).collect();

    let mut acc = P::IDENTITY;
    for w in (0..windows).rev() {
        // Shift the accumulator up by one window before folding this one in.
        // Skipped on the first (most significant) pass, where `acc` is still
        // the identity and the doublings would be wasted.
        if w + 1 != windows {
            for _ in 0..c {
                acc.double_assign();
            }
        }

        // `Option` rather than starting every bucket at the identity: most
        // buckets stay empty on a `2^16`-point MSM with a 12-bit window, and an
        // add into the identity would still be a full chip call.
        let mut buckets: Vec<Option<P>> = vec![None; n_buckets];
        for (s, base) in scalars.iter().zip(bases.iter()) {
            let k = window_at(s, w, c);
            if k != 0 {
                match &mut buckets[k - 1] {
                    slot @ None => *slot = Some(base.clone()),
                    Some(b) => *b += base,
                }
            }
        }

        // Summation by parts: walking the buckets downwards, the running sum
        // holds `Σ_{j >= k} bucket[j]`, so adding it once per step accumulates
        // `Σ k · bucket[k]` without multiplying anything.
        let mut running = P::IDENTITY;
        for b in buckets.into_iter().rev() {
            if let Some(b) = b {
                running += b;
            }
            acc += &running;
        }
    }
    acc
}
