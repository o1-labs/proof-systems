use crate::prover::ProofEvaluations;
use algebra::{
    curves::{short_weierstrass_jacobian::GroupAffine, SWModelParameters},
    BigInteger, Field, FpParameters, PairingEngine, PrimeField,
};
use oracle::poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge};

const DIGEST_LENGTH_IN_LIMBS: usize = 4;
const CHALLENGE_LENGTH_IN_LIMBS: usize = 2;

const HIGH_ENTROPY_LIMBS: usize = 4;

pub trait FqSponge<Fq: Field, G, Fr> {
    fn new(p: ArithmeticSpongeParams<Fq>) -> Self;
    fn absorb_g(&mut self, g: &[G]);
    fn absorb_fr(&mut self, x: &Fr);
    fn challenge(&mut self) -> Fr;

    fn digest(self) -> Fr;
}

pub trait FrSponge<Fr: Field> {
    fn new(p: ArithmeticSpongeParams<Fr>) -> Self;
    fn absorb(&mut self, x: &Fr);
    fn challenge(&mut self) -> Fr;
    fn absorb_evaluations(&mut self, x_hat_beta1: &[Fr], e: &ProofEvaluations<Fr>);
}

pub trait SpongePairingEngine: PairingEngine {
    type FqSponge: FqSponge<Self::Fq, Self::G1Affine, Self::Fr>;
    type FrSponge: FrSponge<Self::Fr>;
}

pub struct DefaultFqSponge<P: SWModelParameters> {
    params: ArithmeticSpongeParams<P::BaseField>,
    sponge: ArithmeticSponge<P::BaseField>,
    last_squeezed: Vec<u64>,
}

pub struct DefaultFrSponge<Fr: Field> {
    params: ArithmeticSpongeParams<Fr>,
    sponge: ArithmeticSponge<Fr>,
    last_squeezed: Vec<u64>,
}

fn pack<B: BigInteger>(limbs_lsb: &[u64]) -> B {
    let mut res: B = 0.into();
    for &x in limbs_lsb.iter().rev() {
        res.muln(64);
        res.add_nocarry(&x.into());
    }
    res
}

impl<Fr: PrimeField> DefaultFrSponge<Fr> {
    fn squeeze(&mut self, num_limbs: usize) -> Fr {
        if self.last_squeezed.len() >= num_limbs {
            let last_squeezed = self.last_squeezed.clone();
            let (limbs, remaining) = last_squeezed.split_at(num_limbs);
            self.last_squeezed = remaining.to_vec();
            Fr::from_repr(pack::<Fr::BigInt>(&limbs))
        } else {
            let x = self.sponge.squeeze(&self.params).into_repr();
            self.last_squeezed.extend(x.as_ref());
            self.squeeze(num_limbs)
        }
    }
}

impl<P: SWModelParameters> DefaultFqSponge<P>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn squeeze(&mut self, num_limbs: usize) -> P::ScalarField {
        if self.last_squeezed.len() >= num_limbs {
            let last_squeezed = self.last_squeezed.clone();
            let (limbs, remaining) = last_squeezed.split_at(num_limbs);
            self.last_squeezed = remaining.to_vec();
            P::ScalarField::from_repr(pack(&limbs))
        } else {
            let x = self.sponge.squeeze(&self.params).into_repr();
            self.last_squeezed
                .extend(&x.as_ref()[0..HIGH_ENTROPY_LIMBS]);
            self.squeeze(num_limbs)
        }
    }
}

impl<Fr: PrimeField> FrSponge<Fr> for DefaultFrSponge<Fr> {
    fn new(params: ArithmeticSpongeParams<Fr>) -> DefaultFrSponge<Fr> {
        DefaultFrSponge {
            params,
            sponge: ArithmeticSponge::new(),
            last_squeezed: vec![],
        }
    }

    fn absorb(&mut self, x: &Fr) {
        self.last_squeezed = vec![];
        self.sponge.absorb(&self.params, &[*x]);
    }

    fn challenge(&mut self) -> Fr {
        self.squeeze(CHALLENGE_LENGTH_IN_LIMBS)
    }

    fn absorb_evaluations(&mut self, x_hat_beta1: &[Fr], e: &ProofEvaluations<Fr>) {
        self.last_squeezed = vec![];
        // beta1 evaluations
        self.sponge.absorb(&self.params, x_hat_beta1);
        for x in &[&e.w, &e.g1, &e.h1, &e.za, &e.zb] {
            self.sponge.absorb(&self.params, x);
        }

        // beta2 evaluations
        for x in &[&e.g2, &e.h2] {
            self.sponge.absorb(&self.params, x);
        }

        // beta3 evaluations
        for x in &[&e.g3, &e.h3] {
            self.sponge.absorb(&self.params, x);
        }
        for t in &[&e.row, &e.col, &e.val] {
            for x in *t {
                self.sponge.absorb(&self.params, x);
            }
        }
    }
}

impl<P: SWModelParameters> FqSponge<P::BaseField, GroupAffine<P>, P::ScalarField>
    for DefaultFqSponge<P>
where
    P::BaseField: PrimeField,
    <P::BaseField as PrimeField>::BigInt: Into<<P::ScalarField as PrimeField>::BigInt>,
{
    fn new(params: ArithmeticSpongeParams<P::BaseField>) -> DefaultFqSponge<P> {
        DefaultFqSponge {
            params,
            sponge: ArithmeticSponge::new(),
            last_squeezed: vec![],
        }
    }

    fn absorb_g(&mut self, g: &[GroupAffine<P>]) {
        self.last_squeezed = vec![];
        for g in g.iter()
        {
            if g.infinity {
                panic!("marlin sponge got zero curve point");
            } else {
                self.sponge.absorb(&self.params, &[g.x]);
                self.sponge.absorb(&self.params, &[g.y]);
            }
        }
    }

    fn absorb_fr(&mut self, x: &P::ScalarField) {
        self.last_squeezed = vec![];
        // Big endian
        let bits: Vec<bool> = x.into_repr().to_bits();

        if <P::ScalarField as PrimeField>::Params::MODULUS
            < <P::BaseField as PrimeField>::Params::MODULUS.into()
        {
            self.sponge.absorb(
                &self.params,
                &[P::BaseField::from_repr(<P::BaseField as PrimeField>::BigInt::from_bits(&bits))],
            );
        } else {
            let low_bits = &bits[1..];

            let high_bit = if bits[0] {
                P::BaseField::one()
            } else {
                P::BaseField::zero()
            };
            self.sponge.absorb(
                &self.params,
                &[P::BaseField::from_repr(<P::BaseField as PrimeField>::BigInt::from_bits(
                    &low_bits,
                ))],
            );
            self.sponge.absorb(&self.params, &[high_bit]);
        }
    }

    fn digest(mut self) -> P::ScalarField {
        self.squeeze(DIGEST_LENGTH_IN_LIMBS)
    }

    fn challenge(&mut self) -> P::ScalarField {
        self.squeeze(CHALLENGE_LENGTH_IN_LIMBS)
    }
}
