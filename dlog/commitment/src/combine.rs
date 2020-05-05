use algebra::{
    curves::models::short_weierstrass_jacobian::{GroupAffine as SWJAffine},
    AffineCurve, BitIterator, Field, PrimeField, ProjectiveCurve,
    SWModelParameters
};
use itertools::Itertools;
use rayon::prelude::*;

fn add_pairs_in_place<P:SWModelParameters>(p: &mut Vec<SWJAffine<P>>) {
    let len = if p.len()%2 == 0 {p.len()} else {p.len()-1};
    let mut denominators = p.chunks_exact_mut(2).map
    (
        |p|
        if p[0].x == p[1].x
        {
            if p[1].y == P::BaseField::zero() {P::BaseField::one()} else {p[1].y.double()}
        } else {p[0].x - &p[1].x}
    ).collect::<Vec<_>>();

    algebra::fields::batch_inversion::<P::BaseField>(&mut denominators);

    for (i, d) in (0..len).step_by(2).zip(denominators.iter())
    {
        let j = i/2;
        if p[i+1].is_zero() == true
        {
            p[j] = p[i];
        }
        else if p[i].is_zero() == true
        {
            p[j] = p[i+1];
        }
        else if p[i+1].x == p[i].x && (p[i+1].y != p[i].y || p[i+1].y == P::BaseField::zero())
        {
            p[j] = SWJAffine::<P>::zero();
        }
        else if p[i+1].x == p[i].x && p[i+1].y == p[i].y
        {
            let sq = p[i].x.square();
            let s = (sq.double() + &sq + &P::COEFF_A) * d;
            let x = s.square() - &p[i].x.double();
            let y = -p[i].y - &(s * &(x - &p[i].x));
            p[j].x = x;
            p[j].y = y;
        }
        else
        {
            let s = (p[i].y - &p[i+1].y) * d;
            let x = s.square() - &p[i].x - &p[i+1].x;
            let y = -p[i].y - &(s * &(x - &p[i].x));
            p[j].x = x;
            p[j].y = y;
        }
    }

    let len = p.len();
    if len % 2 == 1
    {
        p[len/2] = p[len-1];
        p.truncate(len/2+1);
    }
    else
    {
        p.truncate(len/2);
    }
}

fn batch_add_assign<P:SWModelParameters>(
    mut denominators: &mut [P::BaseField],
    v0: &mut [SWJAffine<P>],
    v1: &[SWJAffine<P>] ) {
    let n = v0.len();

    for i in 0..n {
        let p0 = v0[i];
        let p1 = v1[i];
        let d = 
            if p0.x == p1.x
            {
                if p1.y == P::BaseField::zero() {P::BaseField::one()} else {p1.y.double()}
            } else {p0.x - &p1.x};
        denominators[i] = d;
    }

    algebra::fields::batch_inversion::<P::BaseField>(&mut denominators);

    for (i, d) in (0..n).zip(denominators.iter())
    {
        let p0 = v0[i];
        let p1 = v1[i];

        if p1.is_zero() == true {
        }
        else if p0.is_zero() == true
        {
            v0[i] = p1;
        }
        else if p1.x == p0.x && (p1.y != p0.y || p1.y == P::BaseField::zero())
        {
            v0[i] = SWJAffine::<P>::zero();
        }
        else if p1.x == p0.x && p1.y == p0.y
        {
            let sq = p0.x.square();
            let s = (sq.double() + &sq + &P::COEFF_A) * d;
            let x = s.square() - &p0.x.double();
            let y = -p0.y - &(s * &(x - &p0.x));
            v0[i].x = x;
            v0[i].y = y;
        }
        else
        {
            let s = (p0.y - &p1.y) * d;
            let x = s.square() - &p0.x - &p1.x;
            let y = -p0.y - &(s * &(x - &p0.x));
            v0[i].x = x;
            v0[i].y = y;
        }
    }
}

fn batch_double_in_place<P:SWModelParameters>(p: &mut [SWJAffine<P>]) {
    let mut denominators = p.iter().map(|p| p.y.double()).collect::<Vec<_>>();
    algebra::fields::batch_inversion::<P::BaseField>(&mut denominators);

    let n = p.len();

    // TODO: Use less memory
    for i in 0..n {
        let d = denominators[i];
        let sq = p[i].x.square();
        let s = (sq.double() + &sq + &P::COEFF_A) * &d;
        let x = s.square() - &p[i].x.double();
        let y = -p[i].y - &(s * &(x - &p[i].x));
        p[i].x = x;
        p[i].y = y;
    }
}

fn affine_combine_base<P: SWModelParameters>(g1: &[SWJAffine<P>], g2: &[SWJAffine<P>], x1: P::ScalarField, x2: P::ScalarField) -> Vec<SWJAffine<P>> {
    let n = g1.len();

    let g1g2 = {
        let mut v : Vec<_> = (0..2*n).map(|i| {
            let j = i / 2;
            if i % 2 == 0 {
                g1[j]
            } else {
                g2[j]
            }
        }).collect();
        add_pairs_in_place(&mut v);
        v
    };
    assert!(g1g2.len() == n);

    let bits1 = BitIterator::new(x1.into_repr());
    let bits2 = BitIterator::new(x2.into_repr());

    let mut p = vec![SWJAffine::<P>::zero(); n];

    let mut denominators = vec![P::BaseField::zero(); n];

    for (b1, b2) in bits1.zip(bits2) {
        // double in place
        {
            for i in 0..n {
                denominators[i] = p[i].y.double();
            }
            algebra::fields::batch_inversion::<P::BaseField>(&mut denominators);

            // TODO: Use less memory
            for i in 0..n {
                let d = denominators[i];
                let sq = p[i].x.square();
                let s = (sq.double() + &sq + &P::COEFF_A) * &d;
                let x = s.square() - &p[i].x.double();
                let y = -p[i].y - &(s * &(x - &p[i].x));
                p[i].x = x;
                p[i].y = y;
            }
        }

        match (b1, b2) {
            (true, true) => batch_add_assign(&mut denominators, &mut p, &g1g2),
            (false, true) => batch_add_assign(&mut denominators, &mut p, &g2),
            (true, false) => batch_add_assign(&mut denominators, &mut p, &g1),
            (false, false) => (),
        }
    }
    p
}

fn affine_window_combine_base<P: SWModelParameters>(g1: &[SWJAffine<P>], g2: &[SWJAffine<P>], x1: P::ScalarField, x2: P::ScalarField) -> Vec<SWJAffine<P>> {
    let n = g1.len();

    let g1g2 = {
        let mut v : Vec<_> = (0..2*n).map(|i| {
            let j = i / 2;
            if i % 2 == 0 {
                g1[j]
            } else {
                g2[j]
            }
        }).collect();
        add_pairs_in_place(&mut v);
        v
    };
    assert!(g1g2.len() == n);

    let windows1 = BitIterator::new(x1.into_repr()).tuples();
    let windows2 = BitIterator::new(x2.into_repr()).tuples();

    let mut p = vec![SWJAffine::<P>::zero(); n];

    let mut denominators = vec![P::BaseField::zero(); n];

    let [
        g01_00, g10_00, g11_00,
        g00_01, g01_01, g10_01, g11_01,
        g00_10, g01_10, g10_10, g11_10,
        g00_11, g01_11, g10_11, g11_11 ] = affine_shamir_window_table(&mut denominators, g1, g2);

    for ((hi_1, lo_1), (hi_2, lo_2)) in windows1.zip(windows2) {
        // double in place
        for _ in 0..2 {
            for i in 0..n {
                denominators[i] = p[i].y.double();
            }
            algebra::fields::batch_inversion::<P::BaseField>(&mut denominators);

            // TODO: Use less memory
            for i in 0..n {
                let d = denominators[i];
                let sq = p[i].x.square();
                let s = (sq.double() + &sq + &P::COEFF_A) * &d;
                let x = s.square() - &p[i].x.double();
                let y = -p[i].y - &(s * &(x - &p[i].x));
                p[i].x = x;
                p[i].y = y;
            }
        }

        match ((hi_1, lo_1), (hi_2, lo_2)) {
            ((false, false), (false, false)) => (),
            ((false, true), (false, false)) => batch_add_assign(&mut denominators, &mut p, &g01_00),
            ((true, false), (false, false)) => batch_add_assign(&mut denominators, &mut p, &g10_00),
            ((true, true), (false, false)) => batch_add_assign(&mut denominators, &mut p, &g11_00),

            ((false, false), (false, true)) => batch_add_assign(&mut denominators, &mut p, &g00_01),
            ((false, true), (false, true)) => batch_add_assign(&mut denominators, &mut p, &g01_01),
            ((true, false), (false, true)) => batch_add_assign(&mut denominators, &mut p, &g10_01),
            ((true, true), (false, true)) => batch_add_assign(&mut denominators, &mut p, &g11_01),

            ((false, false), (true, false)) => batch_add_assign(&mut denominators, &mut p, &g00_10),
            ((false, true), (true, false)) => batch_add_assign(&mut denominators, &mut p, &g01_10),
            ((true, false), (true, false)) => batch_add_assign(&mut denominators, &mut p, &g10_10),
            ((true, true), (true, false)) => batch_add_assign(&mut denominators, &mut p, &g11_10),

            ((false, false), (true, true)) => batch_add_assign(&mut denominators, &mut p, &g00_11),
            ((false, true), (true, true)) => batch_add_assign(&mut denominators, &mut p, &g01_11),
            ((true, false), (true, true)) => batch_add_assign(&mut denominators, &mut p, &g10_11),
            ((true, true), (true, true)) => batch_add_assign(&mut denominators, &mut p, &g11_11),
        }
    }
    p
}

pub fn affine_combine<P: SWModelParameters>(g1: &Vec<SWJAffine<P>>, g2: &Vec<SWJAffine<P>>, x1: P::ScalarField, x2: P::ScalarField) -> Vec<SWJAffine<P>> {
    const CHUNK_SIZE : usize = 10_000;
    let b : Vec<_> = g1.chunks(CHUNK_SIZE).zip(g2.chunks(CHUNK_SIZE)).collect();
    let v : Vec<_> = b.into_par_iter().map(|(v1, v2)| affine_combine_base(v1, v2, x1, x2)).collect();
    v.concat()
}

pub fn affine_window_combine<P: SWModelParameters>(g1: &Vec<SWJAffine<P>>, g2: &Vec<SWJAffine<P>>, x1: P::ScalarField, x2: P::ScalarField) -> Vec<SWJAffine<P>> {
    const CHUNK_SIZE : usize = 10_000;
    let b : Vec<_> = g1.chunks(CHUNK_SIZE).zip(g2.chunks(CHUNK_SIZE)).collect();
    let v : Vec<_> = b.into_par_iter().map(|(v1, v2)| affine_window_combine_base(v1, v2, x1, x2)).collect();
    v.concat()
}

pub fn combine<G:AffineCurve>(g_lo: &Vec<G>, g_hi: &Vec<G>, x_lo: G::ScalarField, x_hi: G::ScalarField) -> Vec<G> {
    let mut g_proj: Vec<G::Projective> = {
        let pairs: Vec<_> = g_lo.iter().zip(g_hi).collect();
        pairs
            .into_par_iter()
            .map(|(lo, hi)| shamir_sum::<G>(x_lo, *lo, x_hi, *hi))
            .collect()
    };
    G::Projective::batch_normalization(g_proj.as_mut_slice());
    g_proj.par_iter().map(|g| g.into_affine()).collect()
}

pub fn window_combine<G:AffineCurve>(g_lo: &Vec<G>, g_hi: &Vec<G>, x_lo: G::ScalarField, x_hi: G::ScalarField) -> Vec<G> {
    let mut g_proj: Vec<G::Projective> = {
        let pairs: Vec<_> = g_lo.iter().zip(g_hi).collect();
        pairs
            .into_par_iter()
            .map(|(lo, hi)| window_shamir::<G>(x_lo, *lo, x_hi, *hi))
            .collect()
    };
    G::Projective::batch_normalization(g_proj.as_mut_slice());
    g_proj.par_iter().map(|g| g.into_affine()).collect()
}

pub fn shamir_sum<G: AffineCurve>(
    x1: G::ScalarField,
    g1: G,
    x2: G::ScalarField,
    g2: G,
) -> G::Projective {
    let mut g1g2: G::Projective = g1.into_projective();
    g1g2.add_assign_mixed(&g2);
    let g1g2 = g1g2.into_affine();

    let bits1 = BitIterator::new(x1.into_repr());
    let bits2 = BitIterator::new(x2.into_repr());

    let mut res = G::Projective::zero();

    for (b1, b2) in bits1.zip(bits2) {
        res.double_in_place();

        match (b1, b2) {
            (true, true) => res.add_assign_mixed(&g1g2),
            (false, true) => res.add_assign_mixed(&g2),
            (true, false) => res.add_assign_mixed(&g1),
            (false, false) => (),
        }
    }

    res
}

pub fn affine_shamir_window_table<P:SWModelParameters>(
    mut denominators: &mut [P::BaseField],
    g1: &[SWJAffine<P>], g2: &[SWJAffine<P>]) -> [Vec<SWJAffine<P>>; 15] {

    fn assign<A:Copy>(dst: &mut [A], src: &[A]) {
        let n = dst.len();
        for i in 0..n {
            dst[i] = src[i]
        }
    }

    let n = g1.len();

    let mut res : [Vec<_>; 15] = [
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
        vec![SWJAffine::<P>::zero(); n],
    ];

    let [
        g01_00, g10_00, g11_00,
        g00_01, g01_01, g10_01, g11_01,
        g00_10, g01_10, g10_10, g11_10,
        g00_11, g01_11, g10_11, g11_11,
    ] = &mut res;

    assign(g01_00, g1);

    assign(g10_00, g1);
    batch_add_assign(&mut denominators, g10_00, g1);

    assign(g11_00, g10_00);
    batch_add_assign(&mut denominators, g11_00, g1);

    assign(g00_01, g2);

    assign(g01_01, g00_01);
    batch_add_assign(&mut denominators, g01_01, g1);

    assign(g10_01, g01_01);
    batch_add_assign(&mut denominators, g10_01, g1);

    assign(g11_01, g10_01);
    batch_add_assign(&mut denominators, g11_01, g1);

    assign(g00_10, g00_01);
    batch_add_assign(&mut denominators, g00_10, g2);

    assign(g01_10, g00_10);
    batch_add_assign(&mut denominators, g01_10, g1);

    assign(g10_10, g01_10);
    batch_add_assign(&mut denominators, g10_10, g1);

    assign(g11_10, g10_10);
    batch_add_assign(&mut denominators, g11_10, g1);

    assign(g00_11, g00_10);
    batch_add_assign(&mut denominators, g00_11, g2);

    assign(g01_11, g00_11);
    batch_add_assign(&mut denominators, g01_11, g1);

    assign(g10_11, g01_11);
    batch_add_assign(&mut denominators, g10_11, g1);

    assign(g11_11, g10_11);
    batch_add_assign(&mut denominators, g11_11, g1);

    res
}

pub fn window_shamir<G: AffineCurve>(
    x1: G::ScalarField,
    g1: G,
    x2: G::ScalarField,
    g2: G,
) -> G::Projective {
    let [_g00_00, g01_00, g10_00, g11_00, g00_01, g01_01, g10_01, g11_01, g00_10, g01_10, g10_10, g11_10, g00_11, g01_11, g10_11, g11_11] =
        shamir_window_table(g1, g2);

    let windows1 = BitIterator::new(x1.into_repr()).tuples();
    let windows2 = BitIterator::new(x2.into_repr()).tuples();

    let mut res = G::Projective::zero();

    for ((hi_1, lo_1), (hi_2, lo_2)) in windows1.zip(windows2) {
        res.double_in_place();
        res.double_in_place();
        match ((hi_1, lo_1), (hi_2, lo_2)) {
            ((false, false), (false, false)) => (),
            ((false, true), (false, false)) => res.add_assign_mixed(&g01_00),
            ((true, false), (false, false)) => res.add_assign_mixed(&g10_00),
            ((true, true), (false, false)) => res.add_assign_mixed(&g11_00),

            ((false, false), (false, true)) => res.add_assign_mixed(&g00_01),
            ((false, true), (false, true)) => res.add_assign_mixed(&g01_01),
            ((true, false), (false, true)) => res.add_assign_mixed(&g10_01),
            ((true, true), (false, true)) => res.add_assign_mixed(&g11_01),

            ((false, false), (true, false)) => res.add_assign_mixed(&g00_10),
            ((false, true), (true, false)) => res.add_assign_mixed(&g01_10),
            ((true, false), (true, false)) => res.add_assign_mixed(&g10_10),
            ((true, true), (true, false)) => res.add_assign_mixed(&g11_10),

            ((false, false), (true, true)) => res.add_assign_mixed(&g00_11),
            ((false, true), (true, true)) => res.add_assign_mixed(&g01_11),
            ((true, false), (true, true)) => res.add_assign_mixed(&g10_11),
            ((true, true), (true, true)) => res.add_assign_mixed(&g11_11),
        }
    }

    res
}

pub fn shamir_window_table<G: AffineCurve>(g1: G, g2: G) -> [G; 16] {
    let g00_00 = G::prime_subgroup_generator().into_projective();
    let g01_00 = g1.into_projective();
    let g10_00 = {
        let mut g = g01_00;
        g.add_assign_mixed(&g1);
        g
    };
    let g11_00 = {
        let mut g = g10_00;
        g.add_assign_mixed(&g1);
        g
    };

    let g00_01 = g2.into_projective();
    let g01_01 = {
        let mut g = g00_01;
        g.add_assign_mixed(&g1);
        g
    };
    let g10_01 = {
        let mut g = g01_01;
        g.add_assign_mixed(&g1);
        g
    };
    let g11_01 = {
        let mut g = g10_01;
        g.add_assign_mixed(&g1);
        g
    };

    let g00_10 = {
        let mut g = g00_01;
        g.add_assign_mixed(&g2);
        g
    };
    let g01_10 = {
        let mut g = g00_10;
        g.add_assign_mixed(&g1);
        g
    };
    let g10_10 = {
        let mut g = g01_10;
        g.add_assign_mixed(&g1);
        g
    };
    let g11_10 = {
        let mut g = g10_10;
        g.add_assign_mixed(&g1);
        g
    };
    let g00_11 = {
        let mut g = g00_10;
        g.add_assign_mixed(&g2);
        g
    };
    let g01_11 = {
        let mut g = g00_11;
        g.add_assign_mixed(&g1);
        g
    };
    let g10_11 = {
        let mut g = g01_11;
        g.add_assign_mixed(&g1);
        g
    };
    let g11_11 = {
        let mut g = g10_11;
        g.add_assign_mixed(&g1);
        g
    };

    let mut v = vec![
        g00_00, g01_00, g10_00, g11_00, g00_01, g01_01, g10_01, g11_01, g00_10, g01_10, g10_10,
        g11_10, g00_11, g01_11, g10_11, g11_11,
    ];
    G::Projective::batch_normalization(v.as_mut_slice());
    let v: Vec<_> = v.iter().map(|x| x.into_affine()).collect();
    [
        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13],
        v[14], v[15],
    ]
}

#[test]
fn test_batch_double_in_place() {
    use algebra::{UniformRand, fields::bn_382::{Fq, Fp}, curves::bn_382::g::{Bn_382GParameters as P, Affine as GAffine}};

    let n = 10;

    let x : Fq = UniformRand::rand(&mut rand::thread_rng());
    let g = GAffine::prime_subgroup_generator().mul(x.into_repr()).into_affine();

    let mut denominators = vec![Fp::zero(); n];

    let p0 = vec![g; 10];
    let mut p = p0.clone();

    // double in place twice
    for _ in 0..2 {
        for i in 0..n {
            denominators[i] = p[i].y.double();
        }
        algebra::fields::batch_inversion::<Fp>(&mut denominators);

        // TODO: Use less memory
        for i in 0..n {
            let d = denominators[i];
            let sq = p[i].x.square();
            let s = (sq.double() + &sq + &P::COEFF_A) * &d;
            let x = s.square() - &p[i].x.double();
            let y = -p[i].y - &(s * &(x - &p[i].x));
            p[i].x = x;
            p[i].y = y;
        }
    }

    let mut p1 : Vec<_> = p0.iter().map(|x| x.into_projective()).collect();
    for x in p1.iter_mut() {
        x.double_in_place();
        x.double_in_place();
    }

    let p : Vec<_> = p.iter().map(|x| x.into_projective()).collect();

    assert_eq!(p, p1);
}

#[test]
fn test_batch_add_assign() {
    use algebra::{UniformRand, fields::bn_382::{Fq, Fp}, curves::bn_382::g::{Bn_382GParameters as P, Affine as GAffine}};
    let n = 10;

    let mut denominators = vec![Fp::zero(); n];
    let x1 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let g1 = vec![GAffine::prime_subgroup_generator().mul(x1.into_repr()).into_affine(); n];

    let x2 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let g2 = vec![GAffine::prime_subgroup_generator().mul(x2.into_repr()).into_affine(); n];

    let mut res_batch = g1.clone();
    batch_add_assign(&mut denominators, &mut res_batch, &g2);
    let res_batch : Vec<_> = res_batch.iter().map(|x| x.into_projective()).collect();

    let res : Vec<_> = g1.iter().zip(g2.iter()).map(|(g1, g2)| g1.into_projective() + &g2.into_projective()).collect();
    assert_eq!(res, res_batch);
}

#[test]
fn test_shamir_window_table() {
    use algebra::{UniformRand, fields::bn_382::{Fq, Fp}, curves::bn_382::g::{Bn_382GParameters as P, Affine as GAffine}};
    let n = 10;

    let mut denominators = vec![Fp::zero(); n];
    let x1 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let g1 = vec![GAffine::prime_subgroup_generator().mul(x1.into_repr()).into_affine(); n];

    let x2 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let g2 = vec![GAffine::prime_subgroup_generator().mul(x2.into_repr()).into_affine(); n];

    let t_batch = affine_shamir_window_table(&mut denominators, &g1, &g2);

    let t_sings : Vec<_> = g1.iter().zip(g2.iter()).map(|(g1, g2)| shamir_window_table(*g1, *g2)).collect();

    for (i, tbl) in t_sings.iter().enumerate() {
        for j in 0..15 {
            assert_eq!(tbl[1+j], t_batch[j][i]);
        }
    }
}


#[test]
fn bench_combine() {
    use std::time::Instant;
    use algebra::{UniformRand, fields::bn_382::Fq, curves::bn_382::g::{Affine as GAffine}};

    const N: usize = 200_000;
    const N_OVER_2: usize = N / 2;

    let x1 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let x2 = x1.inverse().unwrap();

    let v1: Vec<GAffine> = (0..N_OVER_2)
        .map(|_| GAffine::prime_subgroup_generator())
        .collect();
    let v2: Vec<GAffine> = (0..N_OVER_2)
        .map(|_| GAffine::prime_subgroup_generator())
        .collect();

    let r = {
        let start = Instant::now();
        let res = combine(&v1, &v2, x1, x2);
        println!("combine {:?} {:?}", res.len(), start.elapsed());
        res
    };

    {
        let start = Instant::now();
        let res = affine_window_combine(&v1, &v2, x1, x2);
        println!("affine_window_combine {:?} {:?}", res.len(), start.elapsed());
        assert_eq!(r, res);
    }

    {
        let start = Instant::now();
        let res = affine_combine(&v1, &v2, x1, x2);
        println!("affine_combine {:?} {:?}", res.len(), start.elapsed());
        assert_eq!(r, res);
    };

    {
        let start = Instant::now();
        let res = window_combine(&v1, &v2, x1, x2);
        println!("window_combine {:?} {:?}", res.len(), start.elapsed());
        assert_eq!(r, res);
    };
}

#[bench]
fn bench_window_shamir(b: &mut ::test::Bencher) {
    use algebra::{UniformRand, fields::bn_382::Fq, curves::bn_382::g::{Affine as GAffine}};

    let x1 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let x2 = x1.inverse().unwrap();

    let g1 = GAffine::prime_subgroup_generator();
    let g2 = GAffine::prime_subgroup_generator();

    b.iter(|| {
        window_shamir(x1, g1, x2, g2)
    });
}

#[bench]
fn bench_shamir(b: &mut ::test::Bencher) {
    use algebra::{UniformRand, fields::bn_382::Fq, curves::bn_382::g::{Affine as GAffine}};

    let x1 : Fq = UniformRand::rand(&mut rand::thread_rng());
    let x2 = x1.inverse().unwrap();

    let g1 = GAffine::prime_subgroup_generator();
    let g2 = GAffine::prime_subgroup_generator();

    b.iter(|| {
        shamir_sum(x1, g1, x2, g2)
    });
}

#[test]
fn shamir_equivalence()
{
    use rand_core::OsRng;
    use algebra::{UniformRand, fields::bn_382::{Fq as Fr}, curves::bn_382::g::Affine};
    let rng = &mut OsRng;

    let g1 : Affine = (Affine::prime_subgroup_generator().into_projective() * &Fr::rand(rng)).into_affine();
    let g2 : Affine = (Affine::prime_subgroup_generator().into_projective() * &Fr::rand(rng)).into_affine();

    let x1 = Fr::rand(rng);
    let x2 = Fr::rand(rng);

    assert_eq!(shamir_sum(x1, g1, x2, g2), window_shamir(x1, g1, x2, g2))
}

