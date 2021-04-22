/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk constraints.

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

VBSMPACK gate constraints

    b*(b-1) = 0
    (xp - xt) * s1 = yp – (2b-1)*yt
    (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
    (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xt + xs)
    n1 = 2*n2 + b

GENERIC gate constraints
    n2 = 0

Permutation constraints
    n2(i+1) -> n1(i+2)
    -> xt(i) -> xt(i+2) -> … -> xt(509)
    -> yt(i) -> yt(i+2) -> … -> yt(509)
    -> xp(i)
    -> xp(i+2) -> xs(i) ->
    -> yp(i)
    -> yp(i+2) -> ys(i) ->
    xs(509) ->
    ys(509) ->

The constraints above are derived from the following EC Affine arithmetic equations:

    (xq - xp) * s1 = yq - yp
    s1 * s1 = xp + xq + x1
    (xp – x1) * s1 = y1 + yp

    (x1 – xp) * s2 = y1 – yp
    s2 * s2 = xp + x1 + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    s1^2 = xp + xq + x1
    (xp – x1) * (s1 + s2) = 2*yp
    s2^2 = xp + x1 + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    (2*xp – s1^2 + xq) * (s1 + s2) = 2*yp
    s2^2 = s1^2 - xq + xs
    (xp – xs) * s2 = ys + yp

    =>

    (xq - xp) * s1 = yq - yp
    (2*xp – s1^2 + xq) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
    (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xq + xs)

*****************************************************************************************************************/

use algebra::FftField;
use crate::gate::{CircuitGate};
use crate::wires::{GateWires, COLUMNS};
use array_init::array_init;

pub trait VbmulpackGateType : PartialEq
{
    const VBMUL2: Self;
}

impl<F: FftField, GateType: VbmulpackGateType> CircuitGate<F, GateType>
{
    pub fn create_vbmul2(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::VBMUL2,
            wires,
            c: vec![]
        }
    }

    pub fn verify_vbmul2(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][self.row+1]);

        self.typ == GateType::VBMUL2
        &&
        // verify booleanity of the scalar bit
        this[3] == this[3].square()
        &&
        // (xp - xt) * s1 = yp – (2*b-1)*yt
        (next[2] - &this[0]) * &this[2] == next[3] - &(this[1] * &(this[3].double() - F::one()))
        &&
        // (2*xp – s1^2 + xt) * ((xp – xs) * s1 + ys + yp) = (xp – xs) * 2*yp
        (next[2].double() + &this[0] - &this[2].square()) * &(this[2] * &(next[2] - &next[0]) + &next[1] + &next[3])
        ==
        next[3].double() * &(next[2] - &next[0])
        &&
        // (ys + yp)^2 = (xp – xs)^2 * (s1^2 – xt + xs)
        (next[1] + &next[3]).square() == (next[2] - &next[0]).square() * &(this[2].square() + &next[0] - &this[0])
        &&
        // n1 = 2*n2 + b
        this[4] == next[4].double() + &this[3]
    }

    pub fn vbmul2(&self) -> F {if self.typ == GateType::VBMUL2 {F::one()} else {F::zero()}}
}
