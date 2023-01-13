# Endomorphism trick

section 6.2 of https://eprint.iacr.org/2019/1021.pdf (also see https://hackmd.io/PiiHHd3fSGmnBiBKSwyQEQ)

* we have challenges (that we obtain by squeezing the sponge, truncate the result to 128 bits, and interpret it as a field element)
* we do stuff with our challenges
* we multiply them to other stuff
  * e.g. in the permutation: `gamma + beta * stuff`
  * e.g. in the plookup: `joint_combinator * stuff + joint_combinator^2 * stuff + ...`
  * e.g. in the composition polynomial: `alpha * gate1 + alpha^2 * gate2 + ...`

btw here's how we obtain challenges:

```text
base_sponge.squeeze() -> 2 field elements in base field (255 bits) -> take the first field element -> truncate it to 128 bits -> reinterpret it as a scalar field element
```

whole point is to randomize, we don't need 255 bits of randomness, 128 bits is enough.

## kay, so?

* the way these challenges in the verifier (circuit) is different
* sometimes we multiply challenges to commitments, so these are scalar multiplications and not field multiplications
* e.g. `[beta] commitment`
* in a verifier _circuit_ a scalar multiplication is costly (takes hundreds of gates)
* the endomorphism trick allows us to do a different scalar multiplication, with a different result, and half the cost
* do we care about the different result? no, as long as it's injective (or 1:1?): the scalar multiplication is still a randomized map to a different point
* so we end up with `[some_func(challenge)] commitment` instead of `[challenge] commitment`

**important question**: do we actually always use challenges as scalar multiplications? If not, we don't need this trick.

it looks like, at least for gamma (which is only added) we don't use the endo trick. Looks like for beta we don't use it either?

we use it for: u, v, joint_combiner_field, alpha, zeta

(zeta is the weirdest use to me, what if we halve the security due to this?)

## the algorithm

```text
Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q
```

^
this is only used in the verifier circuit, in kimchi

I think this code in kimchi computes `some_func(challenge)`, because we don't use _the algorithm_ directly.

```rust
impl<F: PrimeField> ScalarChallenge<F> {
    pub fn to_field_with_length(&self, length_in_bits: usize, endo_coeff: &F) -> F {
        let rep = self.0.into_repr();
        let r = rep.as_ref();

        let mut a: F = 2_u64.into();
        let mut b: F = 2_u64.into();

        let one = F::one();
        let neg_one = -one;

        for i in (0..(length_in_bits as u64 / 2)).rev() {
            a.double_in_place();
            b.double_in_place();

            let r_2i = get_bit(r, 2 * i);
            let s = if r_2i == 0 { &neg_one } else { &one };

            if get_bit(r, 2 * i + 1) == 0 {
                b += s;
            } else {
                a += s;
            }
        }

        a * endo_coeff + b
    }

    pub fn to_field(&self, endo_coeff: &F) -> F {
        let length_in_bits = 64 * CHALLENGE_LENGTH_IN_LIMBS;
        self.to_field_with_length(length_in_bits, endo_coeff)
    }
}
```

## endo_r and endo_q

code that generates the two endo thing for a given curve:

```rust
pub fn endos<G: CommitmentCurve>() -> (G::BaseField, G::ScalarField)
where
    G::BaseField: PrimeField,
{
    let endo_q: G::BaseField = mina_poseidon::sponge::endo_coefficient();
    let endo_r = {
        let potential_endo_r: G::ScalarField = mina_poseidon::sponge::endo_coefficient();
        let t = G::prime_subgroup_generator();
        let (x, y) = t.to_coordinates().unwrap();
        let phi_t = G::of_coordinates(x * endo_q, y);
        if t.mul(potential_endo_r) == phi_t.into_projective() {
            potential_endo_r
        } else {
            potential_endo_r * potential_endo_r
        }
    };
    (endo_q, endo_r)
}
```

**important question**: how does that work?

**important question**: why have two endo things? I don't know.

I think: because we have a base sponge, and a scalar sponge

why is there no symmetry in the endo_q and the endo_r of vesta and pallas?

pallas:

* endo_q = 2D33357CB532458ED3552A23A8554E5005270D29D19FC7D27B7FD22F0201B547
* endo_r = 397E65A7D7C1AD71AEE24B27E308F0A61259527EC1D4752E619D1840AF55F1B1

vesta:

* endo_q = 06819A58283E528E511DB4D81CF70F5A0FED467D47C033AF2AA9D2E050AA0E4F
* endo_r = 12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9
