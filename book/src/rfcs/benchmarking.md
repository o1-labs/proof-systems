# Summary

Adds a benchmarking infrastructure for the crypto stack and some specific
benchmarks. This RFC focuses in proofs-systems, a future RFC will address the Ocaml codebase.

# Motivation

There are two main motivations, to aid development and to facilitate comparisons
with other technologies.  This document proposes a high level approach to
benchmarking the proof-systems. The main concern is to set up an infrastructure
where it is possible to integrate different kinds of benchmarks with minimal
effort. While the specific benchmarks are not an immediate concern, a few
benchmarks of interest will be mentioned later.

# Detailed design

## Types of benchmarks

There are different [metrics](#metrics) that we can collect, and different ways
of presenting them depending of [who is interested](#audience) in them.

### Audience

We can differentiate to groups of people interested in benchmarks:

- Developers working in the crypto stack, mostly our crypto team, where the main
interests are to avoid regressions and make performance improvements.
- People not directly working on the crypto stack, mostly users of our
libraries. This group could also include decision makers comparing other options
or our own marketing team. The focus here is about more general metrics that can
be compared with the competition or used to learn how to most efficiently use
our technology.

Note that some overlap is expected. Some benchmarks will be useful to everyone
while others just to some.

### Metrics

Three metrics are considered: [performance](#performance), [memory](#memory),
and [hardware utilization](#hardware-utilization). The main metrics are
performance and memory. The hardware utilization metric has a more limited
scope.

#### Performance

Performance basically amounts to execution time. Nonetheless, this may be the
hardest to measure, because the environment can have a considerable effect over
the results. Some high quality machine would be required, ideally a fully
dedicated one to minimize noise. Further in this document, we mention a way of
measuring that overcomes noise problem.  It can be subdivided into 2 other
metrics or alternative approaches:

: Execution time The simplest approach. It runs the program several times and
returns the overall average execution time. This benchmark might become slow in
cases where the program takes too much time to run. In such scenarios, this
benchmark can be made faster by reducing the number of samples (i.e., worst
precision) it uses. This is one of the most interesting metrics for external
users and a key datapoint to compare how our proof-system fares against
competitors. The execution time metric can also help our engineering teams as a
metric to identify regressions or to verify performance improvements.

: CPU instructions Instead of recording execution time, this method counts the
number of cpu instructions used in a program execution, not very useful for
external developer given that it doesn't translate directly to time. It is
mostly useful to our engineering teams as an alternative to execution time, it
is faster given that you only have to run it once to collect the information,
and can be run on cheap machines without significative noise given that
execution time doesn't affect the number of instructions. Additionally, the
tools used to measure it also collect some other metrics that can be useful to
aide optimization like cache misses and branch mispredictions.

#### Memory

Memory usage is another interesting metric. There are different ways of
measuring memory but the most useful for us is peak memory, as this will tell
whether something can even be used in a particular environment. It can also help
finding errors related to unusual memory usage.  Memory usage is easier to
measure, as it does not appear to depend as much on the noise of the environment
as long as there is enough memory.

#### Hardware utilization

It can be of interest in some cases to measure how much of the available
resources are actually used, ideally the same computer will take half the time
with twice the resources, unfortunately this isn't always the case and sometimes
additional resources go unused.  This doesn't change that often, the main
utility of these benchmarks is just to detect low utilization so that it can be
improved.  Hardware utilization could include many things, GPU acceleration for
example if we were to start using it, but for now will only include CPU/core
utilization.

## Where to run the benchmarks

To start everyone with the resources should be able to run the benchmarks
locally, additionally we may want some of the benchmarks to run in CI to detect
regressions. Some benchmarks may be considerably expensive to run, a decision
will have to be made about which benchmarks to run and how often we should run
them.

## Parameters

It will be of interest parameterizing some benchmarks, for example benchmarking
verification time but doing it with different circuits sizes, that would show
how performance scales with the size of the circuit.  The introduction of
parameters doesn't cause any fundamental change to the benchmarks, but it can
considerably increase the cost of running them, making them more the kind of
benchmarks that we may not want to run every single time in CI.

## Benchmark classes

Next the classes of benchmarks to consider, they are different combinations of
metrics and consumers.

| benchmarks        | metric   | for external use | for internal use | regression test | noise sensitive  |
| ----------------- | -------- | ---------------- | ---------------- | --------------- | ---------------- |
| time              | time     | yes              | yes              | yes             | yes              |
| time flamegraph   | time     | no               | yes              | no              | no               |
| instructions      | time     | no               | yes              | yes             | no               |
| memory            | memory   | yes              | yes              | yes             | no               |
| memory flamegraph | memory   | no               | yes              | no              | no               |

### Kimchi time

One of the simplest measuring running time, can be a specific case or allow more
flexibility by introducing parameters like for example different circuit sizes.
We already have most of the infrastructure for this with
[criterion](https://crates.io/crates/criterion). We would ideally have a
dedicated computer. However, considering that there aren't that many PRs in
proof-systems, the requirements shouldn't be that high.

### Kimchi time flamegraph

This can be considered a variant of the [previous](#kimchi-time). Some more
research is required but this information ideally can be generated from the
already existing benchmarks with little to no changes.  This may not be as
interesting to have in CI, but can be useful to run locally for those working in
optimizations.

### Kimchi instructions

This is basically counting the CPU instructions that takes to run some code,
could be use as an alternative for CI given that it won't be affected by noise
and can work in any computer. It would also be faster by running the code only
once. The implementation will require a bit more research but one option is the
crate [iai](https://crates.io/crates/iai), with some thinking it could be
possible to have this and the time benchmarks share the same code.  Is worth
mentioning that the result are specific to the code and even the computer
running the benchmark and thus not useful for comparisons with other projects.

### Kimchi memory

Similar to time, but with memory, the constraints are different in some ways,
noise is not generally a problem and any computer can be used, and also requires
less sampling and should run faster. This is to some degree already implemented
through a custom measurement for criterion, and in practice can be slower than
measuring time, the instrumentation makes it run slower and some limitations
in criterion require to run the code more than necessary. With that in mind, the
best would be to run just a subset of these benchmark for regressions and let
the others be run at discretion.

### Kimchi memory flamegraph

Similar to the time flamegraph, ideally can be made from the memory benchmark
without much additional work.

## Benchmarks

Here is a non exhaustive list of benchmarks.

### Kimchi hash chain

Benchmarking different aspects of a circuit proving a hash chain.

- The length of the hash chain can easily be a parameter allowing to measure
different lengths.
- We want memory and time for compilation, proving and verification, it will be
implemented as several benchmarks but they will share most code.
- The number of constraints can be easily shown for each length.  
- This benchmark with some specific length can be used as regression tests in CI.
- The full benchmark with several lengths can be shown at discretion of those
interested running locally, or even added as optional to CI with some way to
trigger it.

### General kimchi benchmarks

Some general benchmarks covering compilation, proving and verifying, both time
and memory. Ideally all of them will be parameterized with different circuit
sizes and a subset can be used as regression tests. We could also add here
benchmarks for the different operations of our polynomial commitments scheme.

# Drawbacks

Beyond the possibility of spending the time in any other project the main
drawback I would be the cost, both in CI running time and dollars. This will
probably be a tradeoff between how much to spend and how much to run in CI.

# Rationale and alternatives

The alternative would be to handle benchmarks in a case by case basis, it may be
cheaper at short term to not have to design and implement this shared
infrastructure. Ultimately would be a matter of how much work will be saved
working on benchmarks. The suggested design may also incentivize the creation of
more benchmarks by lowering to barriers to create them.

# Prior art

Right now there are just a few benchmarks covering specific cases that can be
run for command line, mostly in the proof-systems repo. Almost all benchmarks
are also limited to measuring only time.

# Unresolved questions
