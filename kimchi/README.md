# Kimchi

Kimchi is based on [plonk](https://eprint.iacr.org/2019/953.pdf), a zk-SNARK protocol.

## Example

We assume that you already have:

* `gates`: a circuit, which can be expressed as a vector of [CircuitGate](https://o1-labs.github.io/proof-systems/rustdoc/kimchi/circuits/gate/struct.CircuitGate.html)
* a way to produce a `witness`, which can be expressed as a `[Vec<F>; COLUMNS]` (for `F` some field of your chosing)
* `public_size`: the size of the public input

Then, you can create an URS for your circuit in the following way:

```rust,ignore
use kimchi::{circuits::constraints, verifier::verify};
use mina_curves::pasta::{fp::Fp, vesta::{Affine, VestaParameters}, pallas::Affine as Other};
use oracle::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use commitment_dlog::commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve};

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

// compile the circuit
let fp_sponge_params = oracle::pasta::fp_kimchi::params();
let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, public_size).unwrap();

// create an URS
let mut urs = SRS::<Affine>::create(cs.domain.d1.size as usize);
srs.add_lagrange_basis(cs.domain.d1);

// obtain a prover index
let prover_index = {
    let fq_sponge_params = oracle::pasta::fq_kimchi::params();
    let (endo_q, _endo_r) = endos::<Other>();
    Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs)
};

// obtain a verifier index
let verifier_index = prover_index.verifier_index();

// create a proof
let group_map = <Affine as CommitmentCurve>::Map::setup();
let proof =  ProverProof::create::<BaseSponge, ScalarSponge>(
    &group_map, witness, &prover_index);

// verify a proof
verify::<Affine, BaseSponge, ScalarSponge>(&group_map, verifier_index, proof).unwrap();
```

Note that kimchi is specifically designed for use in a recursion proof system, like [pickles](https://medium.com/minaprotocol/meet-pickles-snark-enabling-smart-contract-on-coda-protocol-7ede3b54c250), but can also be used a stand alone for normal proofs.

## Benchmarks

To bench kimchi, we have two types of benchmark engines. 

[Criterion](https://bheisler.github.io/criterion.rs/) is used to benchmark time:

```console
$ cargo criterion -p kimchi --bench proof_criterion
```

The result will appear in `target/criterion/single\ proof/report/index.html` and look like this:

![criterion kimchi](https://i.imgur.com/OGqiuHD.png)

Note that it only does 10 passes. To have more accurate statistics, remove the `.sample_size(10)` line from the [bench](benches/proof_criterion.rs).

The other benchmark uses [iai](https://github.com/bheisler/iai) to perform precise one-shot benchmarking. This is useful in CI, for example, where typical benchmarks are affected by the load of the host running CI.

```console
$ cargo bench -p kimchi --bench proof_iai
```

It will look like this:

<pre>bench_proof_creation
Instructions: 22045968746
L1 Accesses: 27210681906
L2 Accesses: 32019515
RAM Accesses: 3034134
Estimated Cycles: 27476974171
</pre>

## Flamegraph

To obtain a flamegraph:

1. [install required dependencies based on your OS](https://github.com/flamegraph-rs/flamegraph#installation)
2. install cargo-flamegraph:
    ```console
    $ cargo install flamegraph
    ```
3. run cargo flamegraph with `sudo` (or with the option `--root` on mac):
    ```console
    $ # flamegraph of the proof creation:
    $ CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --bin flamegraph --notes "proof creation" -- prove
    $ # flamegraph of the proof verification:
    $ CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --bin flamegraph --notes "proof verification" -- verify
    ```
    the [binary](src/bin/flamegraph.rs) will run forever, so you have to C-c to exit and produce the `flamegraph.svg` file.

Note: lots of good advice on system performance in the [flamegraph repo](https://github.com/flamegraph-rs/flamegraph#systems-performance-work-guided-by-flamegraphs).
