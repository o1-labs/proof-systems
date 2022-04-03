# Poseidon hash

**THIS IS WORK-IN-PROGRESS**

A hash function that is efficient for zk-SNARKs. It is based on the sponge function, with a state composed of field elements and a permutation based on field element operation (addition and exponentiation).

The perumtation is built like SPN block ciphers, with an S-box (exponentiation a group element), adding constants to the state, and matrix multiplication of the state (multiplications and additions) with an MDS matrix.

Since a field element is around 255-bit, a single field element is enough as the capacity of the sponge. The state is therefore often small, with our state being 4 field elements and a rate of 3 field elements.

* main website https://www.poseidon-hash.info/
* our ocaml implementation: https://github.com/minaprotocol/mina/blob/develop/src/lib/random_oracle/random_oracle.mli
* relies on random_oracle_input: https://github.com/minaprotocol/mina/blob/develop/src/lib/random_oracle_input/random_oracle_input.ml
* is instantiated with two types of fields:
    - https://github.com/minaprotocol/mina/blob/develop/src/nonconsensus/snark_params/snark_params_nonconsensus.ml
    - pickles: 
        + seems to rely on zexe code (https://www.youtube.com/watch?v=RItcNRChrzI&t=1732s)

we currently have a few choices:

* specify our own version
* adhere to the [zcash poseidon spec](https://github.com/C2SP/C2SP/pull/3)
* specify an extension of the zcash poseidon spec

## Pseudo-code

```python
# modular exponentiation
def sbox(field_element):
    field_element^5

# apply MDS matrix
def apply_mds(state):
    n = [0, 0, 0]
    n[0] = state[0] * mds[0][0] + state[1] * mds[0][1] + state[2] * mds[0][2]
    n[1] = state[0] * mds[1][0] + state[1] * mds[1][1] + state[2] * mds[1][2]
    n[2] = state[0] * mds[2][0] + state[1] * mds[2][1] + state[2] * mds[2][2]
    return n
    
# a round
def full_round(round, state):
    # sbox
    state[0] = sbox(state[0])
    state[1] = sbox(state[1])
    state[2] = sbox(state[2])

    # apply MDS matrix
    state = apply_mds(state)

    # add round constant
    constant = round_constants[round]
    state[0] += constant[0]
    state[1] += constant[1]
    state[2] += constant[2]

# poseidon is just a number of rounds with different round constants
def poseidon(state, rounds):
    # ARK_INITIAL is not used usually, but if used there's 
    round_offset = 0
    if ARK_INITIAL:
        constant = round_constants[0]
        state[0] += constant[0]
        state[1] += constant[1]
        state[2] += constant[2]
        round_offset = 1
        
    for round in range(round_offset, rounds + round_offset):
        full_round(round, state)
```
