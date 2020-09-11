extern crate num_integer;


use algebra::{
    One, Field, FftField, SquareRootField, Fp256Parameters,
    fields::{FftParameters, Fp256},
};



// Given 
// - an order p field F with p - 1 = t * 2^k, t odd, g an element of order 2^k in F,
// - h : F
// output (c, d) such that
// h = c * g^d, where c is in the orthogonal complement of < g >
// algorithm: first compute c = (h^2^k)^{inv(2^k) mod t}
fn decompose<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(h : Fp256<P>) -> (Fp256<P>, u64) {
    let k = P::TWO_ADICITY as u32;
    let exponent = u64::pow(2, k);
    let t_component : Fp256<P> = h.pow([exponent]);
    let c =  t_component.pow(P::TWO_TO_TWO_ADICITY_INV.as_ref());
    let two_to_k_component =  c.inverse().unwrap() * h;
    let d = two_adic_discrete_log(two_to_k_component);
    (c,d)
}

fn compose<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(c: Fp256<P>, d: u64) ->  Fp256<P> {
    let g : Fp256<P> = FftField::two_adic_root_of_unity();
    let h : Fp256<P> = c * g.pow([d]);
    h
}


// Given 
// - an order p field F with p - 1 = t * 2^e, t odd, g an element of order 2^e in F,
// - h in < g >
// output x such that
// h = g^x
// 
// This uses [this algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
fn two_adic_discrete_log<P: FftParameters + Fp256Parameters>(h : Fp256<P>) -> u64 {
    let e = P::TWO_ADICITY as usize;
    let mut x : u64 = 0;
    assert!(e <= 64);
    let g : Fp256<P> = FftField::two_adic_root_of_unity();
    let g_inv = g.inverse().unwrap();

    {
        let gamma = pow2_pow(g, e - 1); // This should just be -1
        assert_eq!(gamma, -Fp256::<P>::one());
    }

    // Invariant: this is equal to g_inv^x at every iteration
    let mut g_inv_to_x = Fp256::<P>::one();
    // Invariant: this is equal to g_inv^{2^k} at iteration k
    let mut g_inv_to_two_to_k = g_inv;
    for k in 0..e {
        let h_k = pow2_pow(g_inv_to_x * h, e - 1 - k); // This should equal +/- 1
        if !h_k.is_one() {
            x |= 1 << k;
            g_inv_to_x *= g_inv_to_two_to_k;
            g_inv_to_two_to_k.square_in_place();
        }
    }

    x
}

// Compute x^{2^k}
fn pow2_pow<F : Field>(x : F, k : usize) -> F {
    let mut res = x;
    for _ in 0..k {
        res.square_in_place();
    }
    res
}








pub trait DetSquareRootParameters : FftParameters {
    const TWO_TO_TWO_ADICITY_INV: Self::BigInt;
}

pub trait DetSquareRootField : FftField {
    fn det_sqrt(&self) -> Option<Self>;

}



 
impl<P: FftParameters + Fp256Parameters + DetSquareRootParameters> DetSquareRootField for Fp256<P>{
       fn det_sqrt(&self)-> Option<Self>{
           match self.sqrt() {
               None => None,
               Some(x) => {
                   let (c,d) =decompose::<P>(x);
                   let d_deterministic = d & (2_i32.pow(63) as u64);
                   let h = compose::<P>(c, d_deterministic);
                   Some(h)
               }
           }
    
       }
    }


/*
impl<F : FftField + SquareRootField, P : DetSquareRootParameters> DetSquareRootField for F{
    type DetSquareRootParams = P;
    fn det_sqrt<P>(&self)-> Option<Self>{
        match self.sqrt() {
            None => None,
            Some(x) => { 
                let (c,d) =decompose(x);
                let d_deterministic = d & (2.pow(63) as u64);
                (c, d_deterministic)
            }
        }

   }
}
*/

//impl<F: FftField + SquareRootField> DetSquareRootField for F
 //   where 
  //      F: FftField + SquareRootField
//{
 //   type DetSquareRootParams;
  //  fn det_sqrt<DetSquareRootParams>(&self)-> Option<Self>{
 //       match self.sqrt() {
  //          None => None,
  //          Some(x) => { 
  //              let (c,d) =decompose(x);
  //              let d_deterministic = d & (2.pow(63) as u64);
  //              (c, d_deterministic)
  //          }
   //     }

  //  }
//}




// given c of order 2^k, generate a witness to check its order. 
//The witness is cwitness = c^{(2^k)^-1 mod t}. This can be verified by checking
// k squarings of cwitness
fn witness_c_order<P: DetSquareRootParameters + Fp256Parameters>(c : Fp256<P>) -> Fp256<P>{
 
    let cwitness = c.pow(P::TWO_TO_TWO_ADICITY_INV.as_ref());
    c
}




pub struct Witness_correct_sqrt<P: FftParameters + Fp256Parameters>{
    c: Fp256<P>,
    d: u64,
    c_inverse_order: Fp256<P>,
}


pub fn witness_det_sqrt<P: FftParameters + Fp256Parameters + DetSquareRootParameters>(b : Fp256<P>)->  Witness_correct_sqrt<P>{
    let (c,d) : (Fp256<P>, u64) = decompose::<P>(b);
    let cwitness : Fp256<P> = witness_c_order::<P>(c);
    let witnesscd: Witness_correct_sqrt<P> = Witness_correct_sqrt::<P> { c: c, d: d, c_inverse_order : cwitness};
    witnesscd
}

 

