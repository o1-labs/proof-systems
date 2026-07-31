//! The Poseidon permutation run natively on OpenVM's modular type.
//!
//! # Why this exists
//!
//! Under `mina-curves`' `openvm` path a field multiplication is *one* chip
//! instruction, but it is wrapped in a conversion on each operand and one on the
//! result: arkworks stores `[u64; 4]`, `IntMod` stores `[u8; 32]`, and the
//! bridge copies 32 bytes each way. Measured on the mainnet fixture, one
//! permutation cost 119,140 instructions for 1,155 multiplications — about 103
//! instructions per multiply, of which exactly one is the multiply.
//!
//! Doing the whole permutation in `IntMod` moves the conversions to the
//! boundary: 3 in, 3 out, plus the round constants, instead of ~3,465.
//!
//! This is the same lesson as the MSM bridge — attach the chip at the level of
//! the algorithm, not the operation.
//!
//! # Dispatch
//!
//! `poseidon_block_cipher` is generic over `F: Field` and there is no
//! specialization on stable, so the Pasta arms are selected by `TypeId` and
//! anything else falls back to the generic path. `Field: 'static` already, so
//! this costs no extra bound on any caller.
//!
//! Conversion goes through the concrete types' public limbs rather than a slice
//! cast: `TypeId` picks the branch, `downcast_mut` gets a checked reference, and
//! nothing here assumes a memory layout.

use core::any::Any;

use ark_ff::Field;
use mina_curves::pasta::{Fp, Fq, OpenVmFpMod, OpenVmFqMod};
use openvm_algebra_guest::IntMod;

use crate::{constants::SpongeConstants, poseidon::ArithmeticSpongeParams};

/// Little-endian bytes of an arkworks field element.
///
/// Under the `openvm` path the stored limbs are already canonical, so this is a
/// copy and not a Montgomery reduction. It stays correct either way — it is the
/// same accessor `mina-curves` uses.
macro_rules! to_mod {
    ($x:expr, $M:ty) => {{
        let limbs: [u64; 4] = ($x.0).0;
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(limbs.iter()) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        <$M>::from_le_bytes_unchecked(&bytes)
    }};
}

macro_rules! from_mod {
    ($m:expr, $F:ty) => {{
        let bytes = $m.as_le_bytes();
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().expect("8 bytes"));
        }
        <$F>::new_unchecked(ark_ff::BigInt::new(limbs))
    }};
}

/// One permutation, entirely in `IntMod`.
///
/// Mirrors `permutation::poseidon_block_cipher`'s `PERM_HALF_ROUNDS_FULL == 0`
/// branch: optional initial ARK, then `PERM_ROUNDS_FULL` full rounds of
/// S-box → MDS → round constants. The other branches stay on the generic path;
/// the caller checks before dispatching here.
macro_rules! permute {
    ($params:expr, $state:expr, $F:ty, $M:ty, $SC:ty, $FULL:expr) => {{
        let p: &ArithmeticSpongeParams<$F, $FULL> = $params;

        let mds: [[$M; 3]; 3] = [
            [
                to_mod!(p.mds[0][0], $M),
                to_mod!(p.mds[0][1], $M),
                to_mod!(p.mds[0][2], $M),
            ],
            [
                to_mod!(p.mds[1][0], $M),
                to_mod!(p.mds[1][1], $M),
                to_mod!(p.mds[1][2], $M),
            ],
            [
                to_mod!(p.mds[2][0], $M),
                to_mod!(p.mds[2][1], $M),
                to_mod!(p.mds[2][2], $M),
            ],
        ];

        let mut st: [$M; 3] = [
            to_mod!($state[0], $M),
            to_mod!($state[1], $M),
            to_mod!($state[2], $M),
        ];

        // `PERM_INITIAL_ARK` shifts the round-constant index by one, exactly as
        // the generic path does.
        let offset = if <$SC>::PERM_INITIAL_ARK {
            for i in 0..3 {
                st[i] += to_mod!(p.round_constants[0][i], $M);
            }
            1
        } else {
            0
        };

        for r in 0..<$SC>::PERM_ROUNDS_FULL {
            // S-box: x^7 in four multiplications, the same schedule as
            // `poseidon::sbox`'s hard-coded case.
            for s in st.iter_mut() {
                let x2 = &*s * &*s;
                let x4 = &x2 * &x2;
                let x6 = &x4 * &x2;
                *s = &x6 * &*s;
            }

            // MDS. Nine multiplications, no intermediate trip back to arkworks:
            // this is where the conversions used to be.
            let rc = &p.round_constants[r + offset];
            let new_st: [$M; 3] = [
                &(&(&mds[0][0] * &st[0]) + &(&mds[0][1] * &st[1])) + &(&mds[0][2] * &st[2]),
                &(&(&mds[1][0] * &st[0]) + &(&mds[1][1] * &st[1])) + &(&mds[1][2] * &st[2]),
                &(&(&mds[2][0] * &st[0]) + &(&mds[2][1] * &st[1])) + &(&mds[2][2] * &st[2]),
            ];
            st = new_st;

            // Round constants.
            for i in 0..3 {
                st[i] += to_mod!(rc[i], $M);
            }
        }

        for i in 0..3 {
            $state[i] = from_mod!(st[i], $F);
        }
    }};
}

/// Run the permutation on the chip if `F` is a Pasta field.
///
/// Returns `false` when the caller must fall back to the generic implementation:
/// a non-Pasta field, or a sponge shape this fast path does not implement
/// (partial rounds, or a width other than 3).
pub fn try_block_cipher<F: Field, SC: SpongeConstants, const FULL_ROUNDS: usize>(
    params: &ArithmeticSpongeParams<F, FULL_ROUNDS>,
    state: &mut [F],
) -> bool {
    // Guard the shape before the type: `permute!` is written for a width-3
    // all-full-rounds sponge, which is what `PlonkSpongeConstantsKimchi` is.
    if SC::SPONGE_WIDTH != 3 || SC::PERM_HALF_ROUNDS_FULL != 0 || SC::PERM_ROUNDS_PARTIAL != 0 {
        return false;
    }
    // The S-box schedule below computes x^7 explicitly.
    if SC::PERM_SBOX != 7 || !SC::PERM_FULL_MDS {
        return false;
    }
    if state.len() != 3 {
        return false;
    }

    let params_any = params as &dyn Any;

    if let Some(p) = params_any.downcast_ref::<ArithmeticSpongeParams<Fp, FULL_ROUNDS>>() {
        let mut s = downcast_state::<F, Fp>(state);
        permute!(p, s, Fp, OpenVmFpMod, SC, FULL_ROUNDS);
        write_back::<F, Fp>(state, &s);
        true
    } else if let Some(p) = params_any.downcast_ref::<ArithmeticSpongeParams<Fq, FULL_ROUNDS>>() {
        let mut s = downcast_state::<F, Fq>(state);
        permute!(p, s, Fq, OpenVmFqMod, SC, FULL_ROUNDS);
        write_back::<F, Fq>(state, &s);
        true
    } else {
        false
    }
}

/// Copy a width-3 state out as its concrete type.
///
/// `[F]` is unsized so it cannot be `dyn Any` directly; each element can, and
/// `downcast_ref` is the checked accessor. The `TypeId` branch above has already
/// established `F == T` via the params, so this cannot fail.
fn downcast_state<F: Field, T: Field>(state: &[F]) -> [T; 3] {
    let at = |i: usize| -> T {
        *(&state[i] as &dyn Any)
            .downcast_ref::<T>()
            .expect("state element type matches the params type")
    };
    [at(0), at(1), at(2)]
}

fn write_back<F: Field, T: Field>(state: &mut [F], src: &[T; 3]) {
    for (s, v) in state.iter_mut().zip(src.iter()) {
        *(s as &mut dyn Any)
            .downcast_mut::<T>()
            .expect("state element type matches the params type") = *v;
    }
}
