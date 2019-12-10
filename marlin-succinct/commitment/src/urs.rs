/*****************************************************************************************************************

This source file implements the Marlin universal reference string primitive

*****************************************************************************************************************/

use algebra::{AffineCurve, ProjectiveCurve, Field, PrimeField, PairingEngine, BigInteger, PairingCurve, UniformRand};
use rand_core::RngCore;

// check pairing of a&b vs c
macro_rules! pairing_check
{
    ($a:expr, $b:expr, $c:expr) => {if <E>::pairing($a, $b) != $c {return false;}};
}

pub struct URS<E: PairingEngine>
{
    pub gp: Vec<E::G1Affine>, // g^(x^i) for 0 <= i < d
    pub hn: Vec<E::G2Affine>, // h^(x^i) for -d < i <= 0
    pub hx: E::G2Affine,
    pub prf: E::G1Affine
}

impl<E: PairingEngine> URS<E>
{
    // empty default calback, use as <obj::URS<E>>::callback
    pub fn callback(_i: usize) {}

    // This function creates URS instance for circuits up to depth d
    //     depth: maximal depth of the circuits
    //     rng: randomness source context
    pub fn create
    (
        depth: usize,
        rng: &mut dyn RngCore
    ) -> Self
    {
        let mut g1 = Wnaf::new();
        let mut g1 = g1.base(E::G1Projective::prime_subgroup_generator(), depth * 4);
        let mut g2 = Wnaf::new();
        let mut g2 = g2.base(E::G2Projective::prime_subgroup_generator(), depth * 4);

        fn table<C: AffineCurve>
        (
            mut cur: C::ScalarField,
            step: C::ScalarField,
            num: usize,
            table: &mut Wnaf<usize, &[C::Projective], &mut Vec<i64>>,
        ) -> Vec<C>
        {
            let mut v = vec![];
            for _ in 0..num
            {
                v.push(table.scalar(cur.into_repr()));
                cur *= &step;
            }
            C::Projective::batch_normalization(&mut v);
            v.into_iter().map(|e| e.into_affine()).collect()
        }

        let xp = E::Fr::rand(rng);
        let mut gx = E::G1Projective::prime_subgroup_generator();
        gx.mul_assign(xp);
        let mut hx = E::G2Projective::prime_subgroup_generator();
        hx.mul_assign(xp);

        URS
        {
            gp: table(E::Fr::one(), xp, depth, &mut g1),
            hn: table(E::Fr::one(), xp.inverse().unwrap(), depth, &mut g2),
            prf: E::G1Affine::from(gx),
            hx: E::G2Affine::from(hx)
        }
    }

    // This function updates URS instance and computes the update proof
    //     rng: randomness source context
    //     RETURN: computed zk-proof
    pub fn update
    (
        &mut self,
        rng: &mut dyn RngCore
    )
    {
        fn exponentiate<C: AffineCurve>
        (
            mut cur: C::ScalarField,
            step: C::ScalarField,
            urs: &mut Vec<C>,
        )
        {
            for i in 0..urs.len()
            {
                urs[i] = urs[i].mul(cur).into_affine();
                cur *= &step;
            }
        }

        let xp = E::Fr::rand(rng);
        let xn = xp.inverse().unwrap();

        // Compute the URS update
        exponentiate(E::Fr::one(), xp, &mut self.gp);
        exponentiate(E::Fr::one(), xn, &mut self.hn);
        
        let mut gx = E::G1Projective::prime_subgroup_generator();
        gx.mul_assign(xp);

        self.hx = self.hx.mul(xp).into_affine();
        self.prf = E::G1Affine::from(gx);
    }

    // This function verifies the updated URS against the zk-proof and the previous URS instance
    //     hn1: previous URS gp[1]
    //     randomness source context
    //     RETURN: zk-proof verification status
    pub fn check<F>
    (
        &mut self,
        hp1: E::G2Affine,
        callback: F,
        rng: &mut dyn RngCore
    ) -> bool
        where F: Fn(usize)
    {
        let xy = <E>::pairing(self.prf, hp1);
        // verify hx consistency with zk-proof
        pairing_check!(E::G1Projective::prime_subgroup_generator(), E::G2Projective::from(self.hx), xy);
        // verify gp[1] consistency with zk-proof
        pairing_check!(E::G1Projective::from(self.gp[1]), E::G2Projective::prime_subgroup_generator(), xy);

        let mut g0: Vec<(E::G1Affine, E::Fr)> = vec![];
        let mut g1: Vec<(E::G1Affine, E::Fr)> = vec![];
        let mut h0: Vec<(E::G2Affine, E::Fr)> = vec![];
        let mut h1: Vec<(E::G2Affine, E::Fr)> = vec![];

        for i in 1..self.gp.len()
        {
            let randomiser: Vec::<E::Fr> = (0..2).map(|_| {E::Fr::rand(rng)}).collect();
            // inductively verify gp
            g0.push((self.gp[i], randomiser[0]));
            g1.push((self.gp[i-1], randomiser[0]));
            // inductively verify hn
            h0.push((self.hn[i-1], randomiser[1]));
            h1.push((self.hn[i], randomiser[1]));
            callback(i);
        }
        E::final_exponentiation(&E::miller_loop(&
        [
            (&Self::multiexp(&g0).prepare(), &E::G2Affine::prime_subgroup_generator().prepare()),
            (&Self::multiexp(&g1).prepare(), &(-self.hx).prepare()),
        ])).unwrap() == E::Fqk::one() &&

        E::final_exponentiation(&E::miller_loop(&
        [
            (&E::G1Affine::prime_subgroup_generator().prepare(), &Self::multiexp(&h0).prepare()),
            (&(-self.gp[1]).prepare(), &Self::multiexp(&h1).prepare()),
        ])).unwrap() == E::Fqk::one()
    }

    // This function multipoint exponentiates the array of group and scalar element tuples
    //     RETURN: multipoint exponention result
    pub fn multiexp<G: PairingCurve> (elm: &Vec<(G, G::ScalarField)>) -> G
    {
        let n = elm.len();
        let c = if n < 32 {3u32} else {(f64::from(n as u32)).ln().ceil() as u32};

        let g = elm.iter().map(|s| s.0);
        // Convert all of the scalars into representations
        let mut s = elm.iter().map(|s| s.1.into_repr()).collect::<Vec<_>>();

        let mut windows = vec![];
        let mut buckets = vec![];

        let mask = (1u64 << c) - 1u64;
        let mut cur = 0;
        while cur <= G::ScalarField::size_in_bits()
        {
            let mut acc = G::Projective::zero();
            buckets.truncate(0);
            buckets.resize((1 << c) - 1, G::Projective::zero());
            let g = g.clone();

            for (s, g) in s.iter_mut().zip(g)
            {
                let t = s.as_ref();
                let index = (t[0] & mask) as usize;
                if index != 0 {buckets[index - 1].add_assign_mixed(&g);}
                s.divn(c as u32);
            }

            let mut running_sum = G::Projective::zero();
            for exp in buckets.iter().rev()
            {
                running_sum += exp;
                acc += &running_sum;
            }
            windows.push(acc);
            cur += c as usize;
        }

        let mut acc = G::Projective::zero();
        for window in windows.into_iter().rev()
        {
            for _ in 0..c {acc = acc.double();}
            acc += &window;
        }
        acc.into_affine()
    }
}

// The code below for w-ary non-adjacent form (wNAF) method (for fast
// elliptic curve point multiplication) has been adapted from Rust::Pairing trait

/// Replaces the contents of `table` with a w-NAF window table for the given window size.
pub(crate) fn wnaf_table<G: ProjectiveCurve>(table: &mut Vec<G>, mut base: G, window: usize) {
    table.truncate(0);
    table.reserve(1 << (window - 1));

    let mut dbl = base;
    dbl = dbl.double();

    for _ in 0..(1 << (window - 1)) {
        table.push(base);
        base.add_assign(&dbl);
    }
}

/// Replaces the contents of `wnaf` with the w-NAF representation of a scalar.
pub(crate) fn wnaf_form<S: BigInteger>(wnaf: &mut Vec<i64>, mut c: S, window: usize) {
    wnaf.truncate(0);

    while !c.is_zero() {
        let mut u;
        if c.is_odd() {
            u = (c.as_ref()[0] % (1 << (window + 1))) as i64;

            if u > (1 << window) {
                u -= 1 << (window + 1);
            }

            if u > 0 {
                c.sub_noborrow(&S::from(u as u64));
            } else {
                c.add_nocarry(&S::from((-u) as u64));
            }
        } else {
            u = 0;
        }

        wnaf.push(u);

        c.div2();
    }
}

/// Performs w-NAF exponentiation with the provided window table and w-NAF form scalar.
///
/// This function must be provided a `table` and `wnaf` that were constructed with
/// the same window size; otherwise, it may panic or produce invalid results.
pub(crate) fn wnaf_exp<G: ProjectiveCurve>(table: &[G], wnaf: &[i64]) -> G {
    let mut result = G::zero();

    let mut found_one = false;

    for n in wnaf.iter().rev() {
        if found_one {
            result = result.double();
        }

        if *n != 0 {
            found_one = true;

            if *n > 0 {
                result.add_assign(&table[(n / 2) as usize]);
            } else {
                result.sub_assign(&table[((-n) / 2) as usize]);
            }
        }
    }

    result
}

/// A "w-ary non-adjacent form" exponentiation context.
#[derive(Debug)]
pub struct Wnaf<W, B, S> {
    base: B,
    scalar: S,
    window_size: W,
}

impl<G: ProjectiveCurve> Wnaf<(), Vec<G>, Vec<i64>> {
    /// Construct a new wNAF context without allocating.
    pub fn new() -> Self {
        Wnaf {
            base: vec![],
            scalar: vec![],
            window_size: (),
        }
    }

    /// Given a base and a number of scalars, compute a window table and return a `Wnaf` object that
    /// can perform exponentiations with `.scalar(..)`.
    pub fn base(&mut self, base: G, num_scalars: usize) -> Wnaf<usize, &[G], &mut Vec<i64>> {
        // Compute the appropriate window size based on the number of scalars.
        let window_size = G::recommended_wnaf_for_num_scalars(num_scalars);

        // Compute a wNAF table for the provided base and window size.
        wnaf_table(&mut self.base, base, window_size);

        // Return a Wnaf object that immutably borrows the computed base storage location,
        // but mutably borrows the scalar storage location.
        Wnaf {
            base: &self.base[..],
            scalar: &mut self.scalar,
            window_size,
        }
    }

    /// Given a scalar, compute its wNAF representation and return a `Wnaf` object that can perform
    /// exponentiations with `.base(..)`.
    pub fn scalar(
        &mut self,
        scalar: <<G as ProjectiveCurve>::ScalarField as PrimeField>::BigInt,
    ) -> Wnaf<usize, &mut Vec<G>, &[i64]> {
        // Compute the appropriate window size for the scalar.
        let window_size = G::recommended_wnaf_for_scalar(scalar);

        // Compute the wNAF form of the scalar.
        wnaf_form(&mut self.scalar, scalar, window_size);

        // Return a Wnaf object that mutably borrows the base storage location, but
        // immutably borrows the computed wNAF form scalar location.
        Wnaf {
            base: &mut self.base,
            scalar: &self.scalar[..],
            window_size,
        }
    }
}

impl<'a, G: ProjectiveCurve> Wnaf<usize, &'a [G], &'a mut Vec<i64>> {
    /// Constructs new space for the scalar representation while borrowing
    /// the computed window table, for sending the window table across threads.
    pub fn shared(&self) -> Wnaf<usize, &'a [G], Vec<i64>> {
        Wnaf {
            base: self.base,
            scalar: vec![],
            window_size: self.window_size,
        }
    }
}

impl<'a, G: ProjectiveCurve> Wnaf<usize, &'a mut Vec<G>, &'a [i64]> {
    /// Constructs new space for the window table while borrowing
    /// the computed scalar representation, for sending the scalar representation
    /// across threads.
    pub fn shared(&self) -> Wnaf<usize, Vec<G>, &'a [i64]> {
        Wnaf {
            base: vec![],
            scalar: self.scalar,
            window_size: self.window_size,
        }
    }
}

impl<B, S: AsRef<[i64]>> Wnaf<usize, B, S> {
    /// Performs exponentiation given a base.
    pub fn base<G: ProjectiveCurve>(&mut self, base: G) -> G
    where
        B: AsMut<Vec<G>>,
    {
        wnaf_table(self.base.as_mut(), base, self.window_size);
        wnaf_exp(self.base.as_mut(), self.scalar.as_ref())
    }
}

impl<B, S: AsMut<Vec<i64>>> Wnaf<usize, B, S> {
    /// Performs exponentiation given a scalar.
    pub fn scalar<G: ProjectiveCurve>(
        &mut self,
        scalar: <<G as ProjectiveCurve>::ScalarField as PrimeField>::BigInt,
    ) -> G
    where
        B: AsRef<[G]>,
    {
        wnaf_form(self.scalar.as_mut(), scalar, self.window_size);
        wnaf_exp(self.base.as_ref(), self.scalar.as_mut())
    }
}