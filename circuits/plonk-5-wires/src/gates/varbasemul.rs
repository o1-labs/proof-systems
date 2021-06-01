/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk constraints.

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

VBSM gate constraints

    b*(b-1) = 0
    (xp - xt) * s1 = yp – (2b-1)*yt
    s1^2 - s2^2 = xt - xs
    (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

Permutation constraints

    -> b(i)
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
    s1^2 - s2^2 = xq - xs
    (2*xp + xq – s1^2) * (s1 + s2) = 2*yp
    (xp – xs) * s2 = ys + yp

*****************************************************************************************************************/

use ark_ff::FftField;
use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use array_init::array_init;

impl<F: FftField> CircuitGate<F>
{
    pub fn create_vbmul(row: usize, wires: GateWires) -> Self
    {
        CircuitGate
        {
            row,
            typ: GateType::Vbmul1,
            wires,
            c: vec![]
        }
    }

    pub fn verify_vbmul1(&self, witness: &[Vec<F>; COLUMNS]) -> bool
    {
        let this: [F; COLUMNS] = array_init(|i| witness[i][self.row]);
        let next: [F; COLUMNS] = array_init(|i| witness[i][self.row+1]);

        self.typ == GateType::Vbmul1
        &&
        // verify booleanity of the scalar bit
        this[4] == this[4].square()
        &&
        // (xp - xt) * s1 = yp – (2*b-1)*yt
        (next[2] - &this[0]) * &this[2] == next[3] - &(this[1] * &(this[4].double() - F::one()))
        &&
        // s1^2 - s2^2 = xt - xs
        this[2].square() - &this[3].square() == this[0] - &next[0]
        &&
        // (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
        (next[2].double() + &this[0] - &this[2].square()) * &(this[2] + &this[3]) == next[3].double()
        &&
        // (xp – xs) * s2 = ys + yp
        (next[2] - &next[0]) * &this[3] == next[1] + &next[3]
    }

    pub fn vbmul1(&self) -> F {if self.typ == GateType::Vbmul1 {F::one()} else {F::zero()}}
}
