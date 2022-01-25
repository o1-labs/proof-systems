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
