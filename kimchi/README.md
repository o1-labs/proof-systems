# Kimchi

Kimchi is based on [plonk](https://eprint.iacr.org/2019/953.pdf), a zk-SNARK protocol.

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

## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md) if you are interested in contributing to this project.

## Guidelines

There are three main steps to follow in order to start using this library:

1. Create the circuit for the targetted relation as a vector of gates. You can use our own custom gates as building blocks, or build your own. 

2. Feed the circuit with a witness that will satisfy the relation. This is equivalent to finding (or computing) a correct instantiation of the execution trace. 

3. Generate and verify the proof of the witness for the relation. 

## Example

When using this library, make sure to include in your Cargo.toml the following dependency:

`
[dependencies]
kimchi = { git = "https://github.com/o1-labs/proof-systems" }
`

Here is an example that uses this library. This code takes the output of a hash and makes sure that the prover knows the input to the hash function.

```rust
use itertools::iterate;
use kimchi::circuits::{
    gate::CircuitGate, 
    wires::Wire, 
    polynomials::generic::GenericGateSpec};
use mina_curves::pasta::Fp;
/// create a simple circuit to hash an input
fn create_circuit() -> Vec<CircuitGate<Fp>> {
    let mut gates = vec![];
    let mut gates_row = iterate(0, |&i| i + 1);
    let mut row = || gates_row.next().unwrap();
    // the output to the hash function is a public input
    // and public inputs are handled with generic gates
    gates.push(CircuitGate::create_generic_gadget(
        Wire::new(row()),
        GenericGateSpec::Pub,
        None,
    ));
    gates.push(CircuitGate::create_generic_gadget(
        Wire::new(row()),
        GenericGateSpec::Pub,
        None,
    ));
    gates.push(CircuitGate::create_generic_gadget(
        Wire::new(row()),
        GenericGateSpec::Pub,
        None,
    ));
    // hash a private input
    let poseidon_params = oracle::pasta::fp_kimchi::params();
    let round_constants = &poseidon_params.round_constants;
    let row = row();
    let (g, final_row) = CircuitGate::<Fp>::create_poseidon_gadget(
        row,
        [Wire::new(row), Wire::new(row + 11)], // TODO: this argument should be deleted from the fn
        round_constants,
    );
    gates.extend(g);
    // wire the output to the public input
    // TODO: it'd be nice if we had functions that would do this for us, 
    //       and panic if a permutation is already in place
    let last_row = gates.iter_mut().last().unwrap();
    last_row.wires[0] = Wire { row: 0, col: 0 };
    last_row.wires[1] = Wire { row: 0, col: 1 };
    last_row.wires[2] = Wire { row: 0, col: 2 };
    gates[0].wires[0] = Wire {
        row: final_row,
        col: 0,
    };
    gates[0].wires[1] = Wire {
        row: final_row,
        col: 1,
    };
    gates[0].wires[2] = Wire {
        row: final_row,
        col: 2,
    };
    gates
}
/*
fn create_witness(gates: &Vec<CircuitGate<Fp>>) -> [Vec<Fp>; COLUMNS] {
    // TODO
}
fn verify_proof(gates: Vec<CircuitGate<Fp>>, witness: [Vec<Fp>; COLUMNS], public: &[Fp]) {
    // TODO
}
*/
fn test_example() {
    // first define the circuit
    let gates = create_circuit();
    // then compute the witness for the circuit and the public input
    /*
    let public = /*the output of the hash function*/
    // TODO: we need simple witness generators for each gate
    let mut witness: [Vec<Fp>; COLUMNS] = create_witness(&gates, &public); 
    // generate and verify a proof
    verify_proof(gates, witness, &public);
    */
}
```