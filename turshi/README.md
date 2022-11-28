# Cairo

Cairo is a [StarkWare](https://starkware.co) framework to provide proofs of computation. One can write programs in the Cairo language, and pass its bytecode compilation to a Stark prover. The original Cairo [implementation](https://github.com/starkware-libs/cairo-lang) is written in Python. In this module we propose a version of Cairo in Rust, which can prove statements using the Kimchi zk-SNARK. We call this proof system Turshi.


## Benchmarks

To bench Turshi, we have created a series of unit tests to evaluate our Cairo runner against the [Cairo playground](https://www.cairo-lang.org/playground/). We can also check constraints on instances of executed programs.