


/// Inner-Product Argument Accumulator.
/// https://eprint.iacr.org/2020/499.pdf
/// 
/// An accumulation scheme for polynomial commitments from discrete log.
/// 
struct Accumulator {
    challenges: Vec<()>
}

/// State to pass-through to "Wrap" proof:
struct PassThrough {

}

/// PlonK proof.
/// https://eprint.iacr.org/2019/953.pdf
/// 
/// 
struct Plonk {
    // permutation challenges
    gamma: (),
    beta: (),

    // quotient challenge
    alpha: (),

    // evaluation challenge
    zetta: (),

    // opening challenge
    v: (),
}

struct Proof {
    pass: PassThrough,
    accum: Accumulator,
    plonk: Plonk,       //
}

/// 
/// 
/// TODO: Implements serde::Serialize / serde::Deserialize
struct Minimal {

}

/*
impl Into<Proof> for Minimal {
  
}

impl Into<Minimal> for Proof {

}
*/