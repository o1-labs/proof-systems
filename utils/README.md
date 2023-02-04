# O1-Utils

A collection of utility functions and trait extensions.

## MSM

You can run the MSM benchmark like so:

```console
$ cargo criterion -p o1-utils --bench msm --features gpu
```

You can also run a flamegraph with [cargo flamegraph]() by doing:

```console
$ sudo RUSTFLAGS=-g CARGO_PROFILE_RELEASE_DEBUG=true cargo +nightly flamegraph --bin msm --features gpu
```

on Mac you'll need the `--root` flag:

```console
$ sudo RUSTFLAGS=-g CARGO_PROFILE_RELEASE_DEBUG=true cargo +nightly flamegraph --root --bin msm --features gpu
```
