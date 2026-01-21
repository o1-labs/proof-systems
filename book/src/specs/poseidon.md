# Poseidon hash function

Poseidon is a hash function that can efficiently run in a zk circuit. (See
[poseidon-hash.info](https://www.poseidon-hash.info/)) It is based on the
[sponge function](https://keccak.team/sponge_duplex.html#:~:text=A%20sponge%20function%20is%20a,or%20the%20retrieval%20of%20output.),
with a state composed of field elements and a permutation based on field element
operation (addition and exponentiation).

The permutation contains an S-box (exponentiation of a group element), adding
constants to the state, and matrix multiplication of the state (multiplications
and additions) with an [MDS matrix](https://en.wikipedia.org/wiki/MDS_matrix).

Since a field element is around 255-bit, a single field element is enough as the
capacity of the sponge to provide around 116-bit security.

```admonish
We might want to piggy back on the [zcash poseidon spec](https://github.com/C2SP/C2SP/pull/3) at some point (perhaps by making this an extension of the zcash poseidon spec).
```

## APIs

We define a base sponge, and a scalar sponge. Both must be instantiated when
verifying a proof (this is due to recursion-support baked in Kimchi).

External users of kimchi (or pickles) are most likely to interact with a wrap
proof (see the [pickles specification](./pickles.md)). As such, the sponges they
need to instantiate are most likely to be instantiated with:

- Poseidon-Fp for base sponge
- Poseidon-Fq for the scalar sponge

### Base Sponge

- `new(params) -> BaseSponge`. Creates a new base sponge.
- `BaseSponge.absorb(field_element)`. Absorbs a field element by calling the
  underlying sponge `absorb` function.
- `BaseSponge.absorb_point(point)`. Absorbs an elliptic curve point. If the
  point is the point at infinity, absorb two zeros. Otherwise, absorb the x and
  y coordinates with two calls to `absorb`.
- `BaseSponge.absorb_scalar(field_element_of_scalar_field)`. Absorbs a scalar.
  - If the scalar field is smaller than the base field (e.g. Fp is smaller than
    Fq), then the scalar is casted to a field element of the base field and
    absorbed via `absorb`.
  - Otherwise, the value is split between its least significant bit and the
    rest. Then both values are casted to field elements of the base field and
    absorbed via `absorb` (the high bits first, then the low bit).
- `BaseSponge.digest() -> field_element`. The `squeeze` function of the
  underlying sponge function is called and the first field element is returned.
- `BaseSponge.digest_scalar() -> field_element_of_scalar_field`.
- `BaseSponge.challenge // TODO: specify`.
- `BaseSponge.challenge_fq // TODO: specify`.

### Scalar Sponge

- new(params) -> ScalarSponge
- ScalarSponge.absorb(scalar_field_element)
- ScalarSponge.digest() -> scalar_field_element
- ScalarSponge.challenge // TODO: specify

## Algorithms

Note that every operation is done in the field of the sponge.

In this section we define the high-level algorithm behind the permutation and
the sponge. The permutation is never used directly by users, it is used only by
the sponge function.

### Permutation

In pseudo-code:

```python
def sbox(field_element):
    # modular exponentiation
    return field_element^7

# apply MDS matrix
def apply_mds(state):
    n = [0, 0, 0]
    n[0] = state[0] * mds[0][0] + state[1] * mds[0][1] + state[2] * mds[0][2]
    n[1] = state[0] * mds[1][0] + state[1] * mds[1][1] + state[2] * mds[1][2]
    n[2] = state[0] * mds[2][0] + state[1] * mds[2][1] + state[2] * mds[2][2]
    return n

# a round in the permutation
def apply_round(round, state):
    # sbox
    state[0] = sbox(state[0])
    state[1] = sbox(state[1])
    state[2] = sbox(state[2])

    # apply MDS matrix
    state = apply_mds(state)

    # add round constant
    state[0] += round_constants[round][0]
    state[1] += round_constants[round][1]
    state[2] += round_constants[round][2]

# the permutation
def permutation(state):
    round_offset = 0
    if ARK_INITIAL:
        constant = round_constants[0]
        state[0] += constant[0]
        state[1] += constant[1]
        state[2] += constant[2]
        round_offset = 1

    for round in range(round_offset, FULL_ROUNDS + round_offset):
        apply_round(round, state)
```

### Sponge

In pseudo-code:

```python
def new():
    return {
        "state": [0] * RATE, # `RATE` field elements set to 0
        "mode": "absorbing",
        "offset": 0,
    }

def absorb(sponge, field_element):
    # if we're changing mode, reset the offset
    if sponge.mode == "squeezing":
        sponge.mode = "absorbing"
        sponge.offset = 0
    # we reached the end of the rate, permute
    elif sponge.offset == RATE:
        sponge.state = permutation(sponge.state)
        sponge.offset = 0

    # absorb by adding to the state
    sponge.state[sponge.offset] += field_element
    sponge.offset += 1

def squeeze(sponge):
    # permute when changing mode or when we already squeezed everything
    if sponge.mode == "absorbing" or sponge.offset == RATE:
        sponge.mode = "squeezing"
        sponge.state = permutation(sponge.state)
        sponge.offset = 0

    result = sponge.state[sponge.offset]
    sponge.offset += 1
    return result
```

## Instantiations

We instantiate two versions of Poseidon, one for the field Fp, and one for the
field Fq (see the [pasta specification](./pasta.md)).

Both share the following sponge configuration:

- capacity 1
- rate: 2

and the following permutation configuration:

- number of full rounds: 55
- sbox: 7
- ARK_INITIAL: false

### Poseidon-Fp

You can find the MDS matrix and round constants we use in
[/poseidon/src/pasta/fp_kimchi.rs](https://github.com/o1-labs/proof-systems/tree/master/poseidon/src/pasta/fp_kimchi.rs).

### Poseidon-Fq

You can find the MDS matrix and round constants we use in
[/poseidon/src/pasta/fp_kimchi.rs](https://github.com/o1-labs/proof-systems/tree/master/poseidon/src/pasta/fq_kimchi.rs).

## Test vectors

We have test vectors contained in
[/poseidon/tests/test_vectors/kimchi.json](https://github.com/o1-labs/proof-systems/tree/master/poseidon/tests/test_vectors/kimchi.json).

## Pointers to the OCaml code

- our ocaml implementation:
  https://github.com/minaprotocol/mina/blob/develop/src/lib/random_oracle/random_oracle.mli
- relies on random_oracle_input:
  https://github.com/minaprotocol/mina/blob/develop/src/lib/random_oracle_input/random_oracle_input.ml
- is instantiated with two types of fields:
  - https://github.com/minaprotocol/mina/blob/develop/src/nonconsensus/snark_params/snark_params_nonconsensus.ml
