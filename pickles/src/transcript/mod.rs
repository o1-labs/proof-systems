use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

mod sponge;
mod utils;

use super::MutualContext;

pub use sponge::{ZkSponge, Absorb};

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

struct Public<F: FftField + PrimeField> {
    var: Var<F>,
    size: usize,
}

// A "container type"
struct Side<F: FftField + PrimeField, C: Cs<F>> {
    cs: C,
    constants: Constants<F>,
    public: Vec<Public<F>>, // "export / pass"
    passthrough: Vec<Var<F>>, // passthough fields from this side (to the complement)
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
            public: vec![],
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

pub trait Passable<F: FftField+PrimeField>: Into<Var<F>> {
    const SIZE: usize; // default is full field size
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
    #[must_use]
    pub fn pass<P: Passable<Fp>>(&mut self, val: P) -> (Var<Fr>, Option<Var<Fr>>) {
        let fp: &mut Side<Fp, CsFp> = self.fp.as_mut().unwrap();
        let fr: &mut Side<Fr, CsFr> = self.fr.as_mut().unwrap();

        let var: Var<Fp> = val.into();

        // add to public inputs
        fp.public.push(Public {
            size: P::SIZE,
            var,
        });

        // converts a slice of bits (minimal representative) to a field element
        fn from_bits<F: FftField + PrimeField>(bits: &[bool]) -> F {
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(bits)).unwrap()
        }

        // needs split if:
        // 1. the modulus of Fr is smaller
        // AND
        // 2. the Fp size is greater/equal than Fr
        let mut split = true;
        split &= Fr::Params::MODULUS.into() < Fp::Params::MODULUS.into();
        split &= Fp::Params::MODULUS_BITS < (P::SIZE as u32);

        // convert the witness to a vec of bits
        let bits = var.value.map(|v| v.into_repr().to_bits_le());

        //
        if split {
            // split into high/low(bit)
            let decm = bits.as_ref().map(|b| {
                let h = from_bits(&b[1..b.len()]);
                let l = if b[0] { Fr::one() } else { Fr::zero() };
                (h, l)
            });

            // split and assign
            (fr.cs.var(|| decm.unwrap().0), Some(fr.cs.var(|| decm.unwrap().1)))
        } else {
            // fit everything in high
            (fr.cs.var(|| from_bits(&bits.unwrap()[..])), None)
        }
    }

    pub fn pass_fits<P: Passable<Fp>>(&mut self, val: P) -> Var<Fr> {
        let (high, low) = self.pass(val);
        assert!(low.is_none(), "does not fit, use '.pass' instead");
        high
    }

    pub fn cs(&mut self) -> &mut CsFp {
        self.as_mut()
    }

    pub fn constants(&self) -> &Constants<Fp> {
        self.as_ref()
    }

    /// Receive a message from the prover
    #[must_use]
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
