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

