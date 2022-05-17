use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

mod sponge;
mod utils;

use super::MutualContext;

pub use sponge::ZkSponge;

use utils::{decompose, lift, need_decompose, transfer_hash};

/// Defered hash transcript
///
///
/// # Dealing with Fr elements
///
/// A fresh sponge is initialized on the complement side:
///
/// The intermediate digest value is then
/// provided as part of the statement on the current side:
///  
/// Schematically it looks something like this:
///
/// ```
/// On current side:
///
///   transcript, h1, h2, transcript_new (statement)
///       |       |   |        |
/// m1 -> H       |   |        |
///       |       |   |        |
///       H <-----/   |        |
///       |           |        |
/// c1 <- H (squeeze) |        |
///       |           |        |
/// m2 -> H           |        |
///       |           |        |
///       H <---------/        |
///       |                    |
///       \---------------------
///
/// On complement side:
///
///                        h1
///                         ^
///     a, b, c -> H        |
///                |        |
///     a * b = c  |        |
///                \--------/
///     
///
///
/// ```
///
///
/// Include the final hash state in the statement of the


// A "container type"
struct Side<F: FftField + PrimeField, C: Cs<F>> {
    cs: C,
    constants: Constants<F>,
    passthrough: Var<F>, // passthough fields from this side (to the complement)
    sponge: ZkSponge<F>, // sponge constrained inside the proof system
    bridge: Vec<Var<F>>, // "exported sponge states", used to merge transcripts across proofs
                         // QUESTION: can this be combined with "passthough"
    merged: bool,        // has the current state been merged with the other side?
}

impl<F: FftField + PrimeField, C: Cs<F>> Side<F, C> {
    fn new(cs: C, constants: Constants<F>) -> Self {
        Self {
            cs,
            sponge: ZkSponge::new(constants.clone()),
            passthrough: vec![],
            constants,
            bridge: vec![],
            merged: true,
        }
    }
}

pub struct Merlin<Fp, Fr, CsFp, CsFr> 
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
        CsFp: Cs<Fp>, 
        CsFr: Cs<Fr>
{
    fp: Option<Side<Fp, CsFp>>,
    fr: Option<Side<Fr, CsFr>>,
}

/// Describes a type which can be "absorbed" into a sponge over a given field
pub trait Absorb<F: FftField + PrimeField> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut ZkSponge<F>);
}

// Can absorb a slice of absorbable elements
impl <F: FftField + PrimeField, T: Absorb<F>> Absorb<F> for [T] {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut ZkSponge<F>) {
        self.iter().for_each(|c| c.absorb(cs, sponge))
    }
}

// Can absorb a fixed length array of absorbable elements
impl <F: FftField + PrimeField, T: Absorb<F>, const N: usize> Absorb<F> for [T; N] {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut ZkSponge<F>) {
        let slice: &[T] = &self[..];
        slice.absorb(cs, sponge)
    }
}

// Can absorb a variable from the same field
impl <F: FftField + PrimeField> Absorb<F> for Var<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut ZkSponge<F>) {
        sponge.absorb(cs, self);
    }
}

/// Describes a type which can be "squeezed" (generated) from the sponge
pub trait Challenge<F: FftField + PrimeField> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut ZkSponge<F>) -> Self;
    
}

// Can generate a variable from the same field
impl <F: FftField + PrimeField> Challenge<F> for Var<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut ZkSponge<F>) -> Self {
        sponge.squeeze(cs)
    }
}

pub struct Msg<T> {
    value: T,
}

impl <T> From<T> for Msg<T> {
    fn from(value: T) -> Self {
        Self{ value }
    }
}

impl <Fp, Fr, CsFp, CsFr> AsMut<CsFp> for Merlin<Fp, Fr, CsFp, CsFr> 
    where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>, 
    CsFr: Cs<Fr> {
        fn as_mut(&mut self) -> &mut CsFp {
            &mut self.fp.as_mut().unwrap().cs
        }
}

impl <Fp, Fr, CsFp, CsFr> AsRef<Constants<Fp>> for Merlin<Fp, Fr, CsFp, CsFr> 
    where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>, 
    CsFr: Cs<Fr> {
        fn as_ref(&self) -> &Constants<Fp> {
            &self.fp.as_ref().unwrap().constants
        }
}

impl <Fp, Fr, CsFp, CsFr> Merlin<Fp, Fr, CsFp, CsFr> 
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
        CsFp: Cs<Fp>, 
        CsFr: Cs<Fr>
{
    pub fn new(
        cs_fp: CsFp,
        cs_fr: CsFr,
        consts_fp: Constants::<Fp>, 
        consts_fr: Constants::<Fr>,
    ) -> Self {
        Self {
            fp: Some(Side::new(cs_fp, consts_fp)),
            fr: Some(Side::new(cs_fr, consts_fr)),
        }
    }

    /// Pass through a variable
    /// 
    /// QUESTION: is the untruncated version used anywhere?
    pub fn pass(&self, val: Var<Fp>) -> (Var<Fr>, Option<Var<Fr>>) {
        // adds variables to the Fr side for the decomposition

        // adds the variables to the Fr "passthough" sponge

        // adds the Fp variable to the passthough vector

        // verifier then:
        //
        // 1. recomputes the decomposition into Fr (outside the proof)
        // 2. recomputes the "passthrough hash"
        // 3. provides the "passthorugh hash" as part of the statement
        //
        // This provides binding between the two proofs and (trivially) 
        // verifies that the decomposition was computed currectly.
     
        unimplemented!()
    }

    /// Pass though a hash / challenge
    /// 
    /// Note that if Fr is smaller than Fp using this method 
    /// can result in a proof which no longer verifies;
    /// but does not violate soundness, since the verifier (trivially) checks for overflow.
    pub fn pass_truncate(&self, val: Var<Fp>) -> Var<Fr> {
        unimplemented!()
    }

    pub fn cs(&mut self) -> &mut CsFp {
        self.as_mut()
    }

    pub fn constants(&self) -> &Constants<Fp> {
        self.as_ref()
    }

    /// Receive a message from the prover
    pub fn recv<H: Absorb<Fp>>(&mut self, msg: Msg<H>) -> H {
        let mut fp: &mut Side<Fp, CsFp> = &mut self.fp.as_mut().unwrap();
        fp.merged = false; // state updated since last squeeze
        msg.value.absorb(&mut fp.cs, &mut fp.sponge);
        msg.value
    }

    /// Generate a challenge over the current field
    pub fn challenge<C: Challenge<Fp>>(&mut self) -> C {
        let mut fr: &mut Side<Fr, CsFr> = &mut self.fr.as_mut().unwrap();
        let fp: &mut Side<Fp, CsFp> = &mut self.fp.as_mut().unwrap();


        // check if we need to merge the states
        if !fr.merged {
            // merge the "foreign sponge" by adding the current state to the statement
            let st_fr: Var<Fr> = fr.sponge.squeeze(&mut fr.cs);
            let st_fp: Var<Fp> = fp.cs.var(|| transfer_hash(st_fr.value.unwrap()));
            fr.bridge.push(st_fr);

            // absorb commitment to "foreign sponge"
            st_fp.absorb(&mut fp.cs, &mut fp.sponge);
            fr.merged = true;
        }

        // squeeze "native sponge" (Fp)
        C::generate(&mut fp.cs, &mut fp.sponge)
    }

    /// Syntactic sugar around: `tx.flip(|tx| tx.recv(val))`
    pub fn recv_fr<H: Absorb<Fr>>(&mut self, msg: Msg<H>) -> H {
        self.flip(|tx| tx.recv(msg))
    }

    /// Syntactic sugar around: `tx.flip(|tx| tx.challenge())`
    pub fn challenge_fr<C: Challenge<Fr>>(mut self) -> C {
        self.flip(|tx| tx.challenge())
    }

    /// Note: this is a "zero cost" operation, which adds no constraints to the proof system
    pub fn flip<T, F: FnOnce(&mut Merlin<Fr, Fp, CsFr, CsFp>) -> T>(&mut self, scope: F) -> T {
        // create flipped instance
        let mut flipped = Merlin{
            fp: self.fr.take(),
            fr: self.fp.take(),
        };

        // invoke scope with other side
        let res = scope(&mut flipped);

        // return to original
        self.fp = flipped.fr;
        self.fr = flipped.fp;

        res
    }
}
