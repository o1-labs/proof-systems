const IVC_NUM_COMMITMENTS: usize; /* Anticipate < 300, so this easily works */
const CIRCUIT_NUM_COMMITMENTS: usize;
/// We fold O = L + r * R
/// In the circuit, we have already Q which is r * R.
///                      L      R          q = r * R                    O
enum FoldingPosition = Left | Right | Right_scaled_nondeterministic | Output;

enum CircuitKind = IVC | Circuit;

/// We have 4 sponges:
/// 1 for Right    - IVC
/// 1 for Right    - Circuit

/// 1 for Right ND - Circuit
/// 1 for Right ND - IVC

/// We do not care in the circuit to have the IVC commitments.

/// get_sponge_state returns the state of the permutation, not the sponge.
/// For our current design of Poseidon, it is 3 elements.
/// i is the ith element of the N commitments we have to fold.
fn poseidon_circuit<Env, F: PrimeField>(env: &mut Env, index: usize, pos: FoldingPosition, kind: CircuitKind) {
    let sponge_state = env.get_sponge_state(pos, kind);
    // It is 2 * 17 elements of 15 bits.
    // We can combine into a biguint
    // [x1, ..., x17]
    // \sum x_i 2^(15 i) -> we just recombine into a native field element.
    // (mr) We don't care if it is over the field order.

    let commitment: (F, F) = env.get_commitment(pos, i, kind);
    // Use one or more rows to do the poseidon thing.
    // Use selectors to turn it on
    // We absorb into the sponge the two field elements that represents the
    // commitment, on one row.
    // -> compute_new_sponge_state takes: 165 columns (apply_permutation) + 2 to absorb the elements
    let new_sponge_state = todo!();
    // Simply update the environment, no constraint.
    env.set_sponge_state(pos, kind, new_sponge_state);
}

// Fits in one row, with some space for supporting operations.
// Enabled/disabled by a selector on each row.
fn ec_add<Env>(env: &mut Env, lhs: ECPoint, rhs: ECPoint) -> ECPoint {
    todo!()
}

// All call to poseidon circuit is one row.
fn ivc_circuit<Env>(env: &mut Env) {
    for i in 0..IVC_NUM_COMMITMENTS {
        // Initial circuit should do something with LHS; ignoring for now to get *something*
        // working
        // Absorb the R
        poseidon_circuit(env, i, Right, IVC);
        // Absorb the Q
        poseidon_circuit(env, i, Right_scaled_nondeterministic, IVC);
    }
    // Here we have N * 2 rows.
    for i in 0..CIRCUIT_NUM_COMMITMENTS {
        // Initial circuit should do something with LHS; ignoring for now to get *something*
        // working
        // Absorb the R
        poseidon_circuit(env, i, Right, Circuit);
        // Absorb the Q
        poseidon_circuit(env, i, Right_scaled_nondeterministic, Circuit);
    }

    { // In a row, use selectors to enable this behaviour
        // folding_chal = r
        // P of Poseidon: s1, s2, s3
        //                |-> folding_chal
        let folding_chal = env.get_sponge_state(env, Right, IVC)[0];
        env.set_folding_chal(folding_chal, IVC);
        // P of Poseidon: s1, s2, s3
        //                     |-> chal_right
        let chal_right = env.get_sponge_state(env, Right, IVC)[1];
        let chal_right_scaled = env.get_sponge_state(env, Right_scaled_nondeterministic, IVC)[0];
        // 
        let chal = chal_right + chal_right_scaled;
        env.set_chal(chal, IVC);
        env.set_chal_acc(chal, IVC);
    }
    // We do the same for the Circuit
    { // In a row, use selectors to enable this behaviour
        // folding_chal = r
        // P of Poseidon: s1, s2, s3
        //                |-> folding_chal
        let folding_chal = env.get_sponge_state(env, Right, Circuit)[0];
        env.set_folding_chal(folding_chal, Circuit);
        // P of Poseidon: s1, s2, s3
        //                     |-> chal_right
        let chal_right = env.get_sponge_state(env, Right, Circuit)[1];
        let chal_right_scaled = env.get_sponge_state(env, Right_scaled_nondeterministic, Circuit)[0];
        // 
        let chal = chal_right + chal_right_scaled;
        env.set_chal(chal, Circuit);
        env.set_chal_acc(chal, Circuit);
    }

    for (kind, num) in [(IVC, IVC_NUM_COMMITMENTS), (Circuit, CIRCUIT_NUM_COMMITMENTS)].into_iter();
        for i in 0..num {
            { // In a row, use selectors to enable this behaviour
                let chal_acc = env.get_chal_acc(kind);
                let folding_chal = env.get_folding_chal(kind);
                let current_chal = env.set_current_chal(chal_acc * folding_chal);
            }
            for j in 0..17 {
                { // In a row, use selectors to enable this behaviour
                    let current_chal = env.get_current_chal();
                    let (low_bits, high_bits) = env.take_15_bits(current_chal);
                    env.set_current_chal(high_bits);
                    let point = env.get_commitment(Right, kind);
                    let bucket = env.get_bucket(j, low_bits, kind);
                    let new_bucket = ec_add(env, bucket, point);
                    env.set_bucket(j, low_bits, kind);
                }
            }
            { // In a row, use selectors to enable this behaviour
                let chal_acc = env.get_chal_acc(kind);
                env.set_current_chal(chal_acc);
            }
            for j in 0..17 {
                { // In a row, use selectors to enable this behaviour
                    let current_chal = env.get_current_chal();
                    let (low_bits, high_bits) = env.take_15_bits(current_chal);
                    env.set_current_chal(high_bits);
                    let point = env.get_commitment(Right_scaled_nondeterministic, kind);
                    let bucket = env.get_bucket(j, low_bits, kind);
                    let new_bucket = ec_add(env, bucket, point);
                    env.set_bucket(j, low_bits, kind);
                }
            }
            { // In a row, use selectors to enable this behaviour
                let new_chal_acc = chal_acc * chal;
                env.set_chal_acc(new_chal_acc, kind);

                let left = env.get_commitment(Left, kind);
                let right_scaled = env.get_commitment(Right_scaled_nondeterministic, kind);
                let res = ec_add(env, left, right_scaled);
                let output = env.get_commitment(Output, kind);
                env.assert_equal_commitment(res, output);
            }
        }
    }
}
