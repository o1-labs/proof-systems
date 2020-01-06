/*****************************************************************************************************************

This source file implements the Marlin universal reference string primitive

*****************************************************************************************************************/

use algebra::{VariableBaseMSM, FixedBaseMSM, AffineCurve, ProjectiveCurve, Field, PrimeField, PairingEngine, PairingCurve, UniformRand};
use std::collections::HashMap;
use rand_core::RngCore;

// check pairing of a&b vs c
macro_rules! pairing_check
{
    ($a:expr, $b:expr, $c:expr) => {if <E>::pairing($a, $b) != $c {return false;}};
}

pub struct URS<E: PairingEngine>
{
    pub gp: Vec<E::G1Affine>, // g^(x^i) for 0 <= i < d
    pub hn: HashMap<usize, E::G2Affine>, // h^(x^-i) for 0 <= i < d
    pub hx: E::G2Affine,
    pub prf: E::G1Affine
}

impl<E: PairingEngine> URS<E>
{
    // empty default calback, use as <obj::URS<E>>::callback
    pub fn callback(_i: usize) {}

    pub fn max_degree(&self) -> usize {
        self.gp.len()
    }

    // This function creates URS instance for circuits up to depth d
    //     depth: maximal depth of the supported circuits
    //     commitment degrees of the committed polynomials for supported circuits
    //     rng: randomness source context
    pub fn create
    (
        depth: usize,
        degrees: Vec<usize>,
        rng: &mut dyn RngCore
    ) -> Self
    {
        let mut x = E::Fr::rand(rng);
        let size_in_bits = E::Fr::size_in_bits();
        let window_size = FixedBaseMSM::get_mul_window_size(depth+1);

        let mut cur = E::Fr::one();
        let mut gp = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>
        (
            size_in_bits,
            window_size,
            &FixedBaseMSM::get_window_table
            (
                size_in_bits,
                window_size,
                E::G1Projective::prime_subgroup_generator()
            ),
            &(0..depth).map(|_| {let s = cur; cur *= &x; s}).collect::<Vec<E::Fr>>(),
        );
        ProjectiveCurve::batch_normalization(&mut gp);

        let mut gx = E::G1Projective::prime_subgroup_generator();
        gx.mul_assign(x);
        let mut hx = E::G2Projective::prime_subgroup_generator();
        hx.mul_assign(x);

        let window_size = FixedBaseMSM::get_mul_window_size(degrees.len()+1);
        x = x.inverse().unwrap();
        let mut hn = FixedBaseMSM::multi_scalar_mul::<E::G2Projective>
        (
            size_in_bits,
            window_size,
            &FixedBaseMSM::get_window_table
            (
                size_in_bits,
                window_size,
                E::G2Projective::prime_subgroup_generator()
            ),
            &degrees.iter().map(|i| x.pow([(depth - *i) as u64])).collect::<Vec<E::Fr>>(),
        );
        ProjectiveCurve::batch_normalization(&mut hn);
        let mut hnh: HashMap<usize, E::G2Affine> = HashMap::new();
        for (i, p) in degrees.iter().zip(hn.iter()) {hnh.insert(depth - *i, p.into_affine());}

        URS
        {
            hn: hnh,
            gp: gp.into_iter().map(|e| e.into_affine()).collect(),
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
        let mut x = E::Fr::rand(rng);
        let mut cur = E::Fr::one();
        for i in 0..self.gp.len()
        {
            self.gp[i] = self.gp[i].mul(cur).into_affine();
            cur *= &x;
        }

        self.prf = E::G1Affine::prime_subgroup_generator().mul(x).into_affine();
        self.hx = self.hx.mul(x).into_affine();

        x = x.inverse().unwrap();
        for p in self.hn.iter_mut()
        {
            *p.1 = p.1.mul(x.pow([*p.0 as u64])).into_affine();
        }
    }

    // This function verifies the updated URS against the zk-proof and the previous URS instance
    //     hn1: previous URS gp[1]
    //     randomness source context
    //     RETURN: zk-proof verification status
    pub fn check
    (
        &mut self,
        hp1: E::G2Affine,
        rng: &mut dyn RngCore
    ) -> bool
    {
        let xy = <E>::pairing(self.prf, hp1);
        // verify hx consistency with zk-proof
        pairing_check!(E::G1Projective::prime_subgroup_generator(), E::G2Projective::from(self.hx), xy);
        // verify gp[1] consistency with zk-proof
        pairing_check!(E::G1Projective::from(self.gp[1]), E::G2Projective::prime_subgroup_generator(), xy);

        let fk = <E>::pairing(E::G1Affine::prime_subgroup_generator(), E::G2Affine::prime_subgroup_generator());
        for x in self.hn.iter()
        {
            // verify hn: e(g^x^i, h^x^-i) = e(g, h)
            if <E>::pairing(self.gp[*x.0], *x.1) != fk {return false}
        }

        let rand = (1..self.gp.len()).map(|_| E::Fr::rand(rng).into_repr()).collect::<Vec<_>>();
        E::final_exponentiation(&E::miller_loop(&
        [
            (&VariableBaseMSM::multi_scalar_mul
                (
                    &(1..self.gp.len()).map(|i| self.gp[i]).collect::<Vec<_>>(),
                    &rand
                ).into_affine().prepare(), &E::G2Affine::prime_subgroup_generator().prepare()
            ),
            (&VariableBaseMSM::multi_scalar_mul
                (
                    &(1..self.gp.len()).map(|i| self.gp[i-1]).collect::<Vec<_>>(),
                    &rand
                ).into_affine().prepare(), &(-self.hx).prepare()
            ),
        ])).unwrap() == E::Fqk::one()
    }
}
