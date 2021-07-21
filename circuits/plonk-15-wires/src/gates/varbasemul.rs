/*****************************************************************************************************************

This source file implements short Weierstrass curve variable base scalar multiplication custom Plonk constraints.

Acc := [2]T
for i = n-1 ... 0:
   Q := (r_i == 1) ? T : -T
   Acc := Acc + (Q + Acc)
return (d_0 == 0) ? Q - P : Q

One-bit round constraints:

S = (P + (b ? T : −T)) + P

VBSM gate constraints for THIS witness row
•	b1*(b1-1) = 0
•	b2*(b2-1) = 0
•	(xp - xt) * s1 = yp – (2b1-1)*yt
•	s1^2 - s2^2 = xt - xr
•	(2*xp + xt – s1^2) * (s1 + s2) = 2*yp
•	(xp – xr) * s2 = yr + yp
•	(xr - xt) * s3 = yr – (2b2-1)*yt
•	S3^2 – s4^2 = xt - xs
•	(2*xr + xt – s3^2) * (s3 + s4) = 2*yr
•	(xr – xs) * s4 = ys + yr
•	n = 32*n_n + 16*b2 + 8*b1 + 4*b3_n + 2*b2_n + b1_n

The constraints above are derived from the following EC Affine arithmetic equations:


    (xq1 - xp) * s1 = yq1 - yp
    s1^2 - s2^2 = xq1 - xr
    (2*xp + xq1 – s1^2) * (s1 + s2) = 2*yp
    (xp – xr) * s2 = yr + yp

    (xq2 - xr) * s3 = yq2 - yr
    s3^2 – s4^2 = xq2 - xs
    (2*xr + xq2 – s3^2) * (s3 + s4) = 2*yr
    (xr – xs) * s4 = ys + yr


VBSM gate constraints for NEXT witness row
•	b1*(b1-1) = 0
•	b2*(b2-1) = 0
•	b3*(b3-1) = 0
•	(xq - xp) * s1 = (2b1-1)*yt - yp
•	(2*xp – s1^2 + xq) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
•	(yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq + xr)
•	(xq - xr) * s3 = (2b2-1)*yt - yr
•	(2*xr – s3^2 + xq) * ((xr – xv) * s3 + yv + yr) = (xr – xv) * 2*yr
•	(yv + yr)^2 = (xr – xv)^2 * (s3^2 – xq + xv)
•	(xq - xv) * s5 = (2b3-1)*yt - yv
•	(2*xv – s5^2 + xq) * ((xv – xs) * s5 + ys + yv) = (xv – xs) * 2*yv
•	(ys + yv)^2 = (xv – xs)^2 * (s5^2 – xq + xs)

The constraints above are derived from the following EC Affine arithmetic equations:


    (xq1 - xp) * s1 = yq1 - yp
    s1^2 - s2^2 = xq1 - xr
    (2*xp + xq1 – s1^2) * (s1 + s2) = 2*yp
    (xp – xr) * s2 = yr + yp

    (xq2 - xr) * s3 = yq2 - yr
    s3^2 – s4^2 = xq2 - xv
    (2*xr + xq2 – s3^2) * (s3 + s4) = 2*yr
    (xr – xv) * s4 = yv + yr

    (xq3 - xv) * s5 = yq3 - yv
    s5^2 – s6^2 = xq3 - xs
    (2*xv + xq3 – s5^2) * (s5 + s6) = 2*yv
    (xv – xs) * s6 = ys + yv

=>

    (xq1 - xp) * s1 = yq1 - yp
    (2*xp – s1^2 + xq1) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
    (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xq1 + xr)

    (xq2 - xr) * s3 = yq2 - yr
    (2*xr – s3^2 + xq2) * ((xr – xv) * s3 + yv + yr) = (xr – xv) * 2*yr
    (yv + yr)^2 = (xr – xv)^2 * (s3^2 – xq2 + xv)

    (xq3 - xv) * s5 = yq3 - yv
    (2*xv – s5^2 + xq3) * ((xv – xs) * s5 + ys + yv) = (xv – xs) * 2*yv
    (ys + yv)^2 = (xv – xs)^2 * (s5^2 – xq3 + xs)


    Row	    0	1	2	3	4	5	6	7	8	9	10	11	12	13	14	Type

       i	xT	yT	xS	yS	xP	yP	n	xr	yr	s1	s2	b1	s3	s4	b2	VBSM
      i+1	s5	b3	xS	yS	xP	yP	n	xr	yr	xv	yv	s1	b1	s3	b2	ZERO

    i+100	xT	yT	xS	yS	xP	yP	n	xr	yr	s1	s2	b1	s3	s4	b2	VBSM
    i+101	s5	b3	xS	yS	xP	yP	n	xr	yr	xv	yv	s1	b1	s3	b2	ZERO


*****************************************************************************************************************/

use crate::gate::{CircuitGate, GateType};
use crate::wires::{GateWires, COLUMNS};
use algebra::FftField;
use array_init::array_init;

macro_rules! zero {
    ($eq:expr) => {
        if $eq != Field::zero() {
            return false;
        }
    };
}

impl<Field: FftField> CircuitGate<Field> {
    // TODO(mimoo): why is `wires` of size 3 if we only use 2?
    // I think it's because we used to use 2
    pub fn create_vbmul(row: usize, wires: &[GateWires; 3]) -> Vec<Self> {
        vec![
            CircuitGate {
                row,
                typ: GateType::Vbmul,
                wires: wires[0],
                c: vec![],
            },
            CircuitGate {
                row: row + 1,
                typ: GateType::Zero,
                wires: wires[1],
                c: vec![],
            },
        ]
    }

    pub fn verify_vbmul(&self, witness: &[Vec<Field>; COLUMNS]) -> bool {
        let this: [Field; COLUMNS] = array_init(|i| witness[i][self.row]);
        let next: [Field; COLUMNS] = array_init(|i| witness[i][self.row + 1]);

        //    0	1	2	3	4	5	6	7	8	9	10	11	12	13	14	Type
        //   xT	yT	xS	yS	xP	yP	n	xr	yr	s1	s2	b1	s3	s4	b2	VBSM

        let xt = this[0];
        let yt = this[1];
        let xs = this[2];
        let ys = this[3];
        let xp = this[4];
        let yp = this[5];
        // TODO(mimoo): missing last constraint?
        let n = this[6];
        let xr = this[7];
        let yr = this[8];
        let s1 = this[9];
        let s2 = this[10];
        let b1 = this[11];
        let s3 = this[12];
        let s4 = this[13];
        let b2 = this[14];

        //    0	1	2	3	4	5	6	7	8	9	10	11	12	13	14	Type
        //   s5	b3	xS	yS	xP	yP	n	xr	yr	xv	yv	s1	b1	s3	b2	ZERO

        // assign again
        // TODO(mimoo): missing ?
        let next_s5 = next[0];
        let next_b3 = next[1];
        let next_xs = next[2];
        let next_ys = next[3];
        let next_xp = next[4];
        let next_yp = next[5];
        // TODO(mimoo): missing ?
        let next_n = next[6];
        let next_xr = next[7];
        let next_yr = next[8];
        let next_xv = next[9];
        let next_yv = next[10];
        let next_s1 = next[11];
        let next_b1 = next[12];
        let next_s3 = next[13];
        let next_b2 = next[14];

        let one = Field::one();

        //
        // checks
        //

        if self.typ == GateType::Vbmul {
            return false;
        }

        // verify booleanity of the scalar bits
        zero!(b1 - b1.square());
        zero!(b2 - b2.square());
        zero!(next_b1 - next_b1.square());
        zero!(next_b2 - next_b2.square());
        zero!(next_b3 - next_b3.square());

        // (xp - xt) * s1 = yp – (2*b1-1)*yt
        zero!((xp - &xt) * &s1 - &yp + &(yt * &(b1.double() - &one)));

        // s1^2 - s2^2 = xt - xr
        zero!(s1.square() - &s2.square() - &xt + &xr);

        // (2*xp + xt – s1^2) * (s1 + s2) = 2*yp
        zero!((xp.double() + &xt - &s1.square()) * &(s1 + &s2) - &yp.double());

        // (xp – xr) * s2 = yr + yp
        zero!((xp - &xr) * &s2 - &yr - &yp);

        // (xr - xt) * s3 = yr – (2b2-1)*yt
        zero!((xr - &xt) * &s3 - &yr + &(yt * &(b2.double() - &one)));

        // S3^2 – s4^2 = xt - xs
        zero!(s3.square() - &s4.square() - &xt + &xs);

        // (2*xr + xt – s3^2) * (s3 + s4) = 2*yr
        zero!((xr.double() + &xt - &s3.square()) * &(s3 + &s4) - &yr.double());

        // (xr – xs) * s4 = ys + yr
        zero!((xr - &xs) * &s4 - &ys - &yr);

        // (xt - xp) * s1 = (2b1-1)*yt - yp
        zero!((xt - &next_xp) * &next_s1 - (next_b1.double() - &one) * &yt + &next_yp);

        // (2*xp – s1^2 + xt) * ((xp – xr) * s1 + yr + yp) = (xp – xr) * 2*yp
        zero!(
            (next_xp.double() - &next_s1.square() + &xt)
                * &((next_xp - &next_xr) * &next_s1 + &next_yr + &next_yp)
                - (next_xp - &next_xr) * &next_yp.double()
        );

        // (yr + yp)^2 = (xp – xr)^2 * (s1^2 – xt + xr)
        zero!(
            (next_yr + &next_yp).square()
                - (next_xp - &next_xr).square() * &(next_s1.square() - &xt + &next_xr)
        );

        // (xt - xr) * s3 = (2b2-1)*yt - yr
        zero!((xt - &next_xr) * &next_s3 - (next_b2.double() - &one) * &yt - &next_yr);

        // (2*xr – s3^2 + xt) * ((xr – xv) * s3 + yv + yr) = (xr – xv) * 2*yr
        zero!(
            (next_xr.double() - &next_s3.square() + &xt)
                * &((next_xr - &next_xv) * &next_s3 + &next_yv + &next_yr)
                - (next_xr - &next_xv) * &next_yr.double()
        );

        // (yv + yr)^2 = (xr – xv)^2 * (s3^2 – xt + xv)
        zero!(
            (next_yv + &next_yr).square()
                - (next_xr - &next_xv).square() * &(next_s3.square() - &xt + &next_xv)
        );

        // (xt - xv) * s5 = (2b3-1)*yt - yv
        zero!((xt - &next_xv) * &next_s5 - (next_b3.double() - &one) * &yt + &next_yv);

        // (2*xv – s5^2 + xt) * ((xv – xs) * s5 + ys + yv) = (xv – xs) * 2*yv
        zero!(
            (next_xv.double() - &next_s5.square() + &xt)
                * &((next_xv - &next_xs) * &next_s5 + &next_ys + &next_yv)
                - (next_xv - &next_xs) * &next_yv.double()
        );

        // (ys + yv)^2 = (xv – xs)^2 * (s5^2 – xt + xs)
        zero!(
            (next_ys + &next_yv).square()
                - (next_xv - &next_xs).square() * &(next_s5.square() - &xt + &next_xs)
        );

        // TODO(mimoo): this constraint is not in the PDF
        zero!(
            ((((next_xr.double() + &b1).double() + &b2).double() + &next_b1).double() + &next_b2)
                .double()
                + &next_xs
                - &xr
        );

        // all good!
        true
    }

    pub fn vbmul(&self) -> Field {
        if self.typ == GateType::Vbmul {
            Field::one()
        } else {
            Field::zero()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::CircuitGate;
    use crate::nolookup::constraints::ConstraintSystem;
    use crate::wires::{GateWires, Wire};
    use algebra::pasta::fp::Fp;
    use algebra::pasta::pallas::{self, Affine};
    use algebra::Zero;
    use algebra_core::curves::AffineCurve;
    use array_init::array_init;

    #[test]
    fn test_gate_vbmul() {
        let wires: GateWires = array_init(|i| Wire { row: 0, col: i });
        let gw = [wires.clone(), wires.clone(), wires.clone()];
        let cg = CircuitGate::<Fp>::create_vbmul(0, &gw);

        // simple example:
        // u = 2^4 + 5 (10101)
        // so k = 0101
        let b1 = 0;
        let b2 = 0;
        let next_b1 = 1;
        let next_b2 = 0;
        let next_b3 = 1;

        // we use pallas because its basefield is Fp, which is what we're doing the calculations with
        let P = Affine::prime_subgroup_generator();

        // init
        let _2P = P + P;
        let xp = _2P.x;
        let yp = _2P.y;

        let witness: [_; COLUMNS] = array_init(|_| vec![Fp::zero(); COLUMNS]);

        let fp_sponge_params = oracle::pasta::fp::params();
        let mut gates = cg.clone();
        gates.extend_from_slice(&cg.clone());
        let cs = ConstraintSystem::<Fp>::create(gates, fp_sponge_params, 0).unwrap();

        for g in cg {
            println!("gate: {:?}", g.verify(&witness, &cs));
        }
    }
}
