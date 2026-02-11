//! Follows approach of `SvdW06` to construct a "near injection" from a field
//! into an elliptic curve defined over that field. WB19 is also a useful
//! reference that details several constructions which are more appropriate in other
//! contexts.
//!
//! Fix an elliptic curve E given by y^2 = x^3 + ax + b over a field "F"
//!   Let f(x) = x^3 + ax + b.
//!
//! Define the variety V to be
//!   (x1, x2, x3, x4) : f(x1) f(x2) f(x3) = x4^2.
//!
//! By a not-too-hard we have a map `V -> E`. Thus, a map of type `F -> V` yields a
//! map of type `F -> E` by composing.
//! Our goal is to construct such a map of type `F -> V`. The paper `SvdW06` constructs
//! a family of such maps, defined by a collection of values which we'll term `params`.
//!
//! OCaml implementation <https://github.com/o1-labs/snarky/blob/2e9013159ad0d1df0af681735b89518befc4be11/group_map/group_map.ml#L4>
//! `SvdW06`: Shallue and van de Woestijne, "Construction of rational points on elliptic curves over finite fields." Proc. ANTS 2006. <https://works.bepress.com/andrew_shallue/1/download/>
//! WB19: Riad S. Wahby and Dan Boneh, Fast and simple constant-time hashing to the BLS12-381 elliptic curve. <https://eprint.iacr.org/2019/403>
//!

#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]

extern crate alloc;

use alloc::vec::Vec;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::{Field, One, Zero};

pub trait GroupMap<F> {
    fn setup() -> Self;
    fn to_group(&self, u: F) -> (F, F);
    fn batch_to_group_x(&self, ts: Vec<F>) -> Vec<[F; 3]>;
}

#[derive(Clone, Copy)]
pub struct BWParameters<G: SWCurveConfig> {
    pub u: G::BaseField,
    pub fu: G::BaseField,
    pub sqrt_neg_three_u_squared_minus_u_over_2: G::BaseField,
    pub sqrt_neg_three_u_squared: G::BaseField,
    pub inv_three_u_squared: G::BaseField,
}

/// returns the right-hand side of the Short Weierstrass curve equation for a given x
fn curve_eqn<G: SWCurveConfig>(x: G::BaseField) -> G::BaseField {
    let mut res = x;
    res *= &x; // x^2
    res += &G::COEFF_A; // x^2 + A
    res *= &x; // x^3 + A x
    res += &G::COEFF_B; // x^3 + A x + B

    res
}

/// finds i for i=start, start+1, ... s.t. f(i) is a valid field
fn find_first<A, K: Field, F: Fn(K) -> Option<A>>(start: K, f: F) -> A {
    let mut i = start;
    loop {
        match f(i) {
            Some(x) => return x,
            None => {
                i += K::one();
            }
        }
    }
}

/// ?
fn potential_xs_helper<G: SWCurveConfig>(
    params: &BWParameters<G>,
    t2: G::BaseField,
    alpha: G::BaseField,
) -> [G::BaseField; 3] {
    let x1 = {
        let mut temp = t2;
        temp.square_in_place(); // t2^2
        temp *= &alpha; // t2^2 * alpha
        temp *= &params.sqrt_neg_three_u_squared; // t2^2 * alpha * sqrt(-3u^2)
        params.sqrt_neg_three_u_squared_minus_u_over_2 - temp // sqrt(-3u^2-u/2) - t2^2 * alpha * sqrt(-3u^2)
    };

    let x2 = -params.u - x1;

    let x3 = {
        let t2_plus_fu = t2 + params.fu;
        let t2_inv = alpha * t2_plus_fu;
        let mut temp = t2_plus_fu.square();
        temp *= &t2_inv;
        temp *= &params.inv_three_u_squared;
        params.u - temp
    };

    [x1, x2, x3]
}

/// ?
fn potential_xs<G: SWCurveConfig>(params: &BWParameters<G>, t: G::BaseField) -> [G::BaseField; 3] {
    let t2 = t.square();
    let mut alpha_inv = t2;
    alpha_inv += &params.fu;
    alpha_inv *= &t2;

    let alpha = alpha_inv.inverse().unwrap_or_else(G::BaseField::zero);

    potential_xs_helper(params, t2, alpha)
}

/// returns the y-coordinate if x is a valid point on the curve, otherwise None
/// TODO: what about sign?
pub fn get_y<G: SWCurveConfig>(x: G::BaseField) -> Option<G::BaseField> {
    let fx = curve_eqn::<G>(x);
    fx.sqrt()
}

fn get_xy<G: SWCurveConfig>(
    params: &BWParameters<G>,
    t: G::BaseField,
) -> (G::BaseField, G::BaseField) {
    let xvec = potential_xs(params, t);
    for x in &xvec {
        if let Some(y) = get_y::<G>(*x) {
            return (*x, y);
        }
    }
    panic!("get_xy")
}

impl<G: SWCurveConfig> GroupMap<G::BaseField> for BWParameters<G> {
    fn setup() -> Self {
        assert!(G::COEFF_A.is_zero());

        // is Field(1) a valid x-coordinate? no? is Field(2) a valid x-coordinate? etc.
        let (u, fu) = find_first(G::BaseField::one(), |u| {
            let fu: G::BaseField = curve_eqn::<G>(u);
            if fu.is_zero() {
                None
            } else {
                Some((u, fu))
            }
        });

        let two = G::BaseField::one() + G::BaseField::one();
        let three = two + G::BaseField::one();

        let three_u_squared = u.square() * three; // 3 * u^2
        let inv_three_u_squared = three_u_squared.inverse().unwrap(); // (3 * u^2)^-1
        let sqrt_neg_three_u_squared = (-three_u_squared).sqrt().unwrap();
        let two_inv = two.inverse().unwrap();
        let sqrt_neg_three_u_squared_minus_u_over_2 = (sqrt_neg_three_u_squared - u) * two_inv;

        Self {
            u,
            fu,
            sqrt_neg_three_u_squared_minus_u_over_2,
            sqrt_neg_three_u_squared,
            inv_three_u_squared,
        }
    }

    fn batch_to_group_x(&self, ts: Vec<G::BaseField>) -> Vec<[G::BaseField; 3]> {
        let t2_alpha_invs: Vec<_> = ts
            .iter()
            .map(|t| {
                let t2 = t.square();
                let mut alpha_inv = t2;
                alpha_inv += &self.fu;
                alpha_inv *= &t2;
                (t2, alpha_inv)
            })
            .collect();

        let mut alphas: Vec<G::BaseField> = t2_alpha_invs.iter().map(|(_, a)| *a).collect();
        ark_ff::batch_inversion::<G::BaseField>(&mut alphas);

        let potential_xs = t2_alpha_invs
            .iter()
            .zip(alphas)
            .map(|((t2, _), alpha)| potential_xs_helper(self, *t2, alpha));
        potential_xs.collect()
    }

    fn to_group(&self, t: G::BaseField) -> (G::BaseField, G::BaseField) {
        get_xy(self, t)
    }
}
