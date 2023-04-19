# Benchmarking RFC

This document proposes a high level approach to benchmarking the crypto stack, mostly kimchi, snarky and pickles. The main concern is to set up an infrastructure where it is possible to integrate different kinds of benchmarks with minimal effort. While the specific benchmarks are not an immediate concern, a few benchmarks of interest will be mentioned later.

## Types of benchmarks

There are different metrics that we can collect, and different ways of presenting them depending of who is interested in them.

### Audience

We can differentiate to groups of people interested in benchmarks:

- Developers working in the crypto stack, mostly our crypto team, where the main interest is to avoid regressions or make performance improvements.
- People working outside of it, mostly users of our libraries, but could also include decision makers comparing other options or our marketing team, here the interest is more about more general metrics that can be compared with the competition or used to learn how to most efficiently use our technology.

Must be mentioned that some overlap should be expected, some benchmarks may be useful for anyone while other just to some.

### Metrics

There are two main metrics, performance and memory, and a smaller one hardware utilization.

#### Performance

Basically execution time, this may be the hardest to measure, because the environment can have a considerable effect over the results, some high quality machine would be required, ideally a fully dedicated one to minimize noise, there is a way of measuring that overcomes noise problems that will be mentioned.
It can be subdivided it 2 other metrics or alternative approaches:

- Execution time: The most simple, run the program in question several times and take the average, it may become quite expensive if the program measured takes some time because that time will be multiplied by the number of samples, in those cases it can be made faster sacrificing precision. This benchmark is one of the most interesting for external users, and one of the main comparison point for evaluating the competition. It can also serve for internal developer as a regression test or to verify performance improvements.

- CPU instructions: This method instead of recording execution time counts the number of cpu instructions used, not very useful for external developer given that it doesn't translate directly to time. It is mostly useful to internal developer as an alternative to execution time, it is faster given that you only have to run it once to collect the information and can be run on cheap machines without significative noise given that execution time doesn't affect the number of instructions. Additionally the tools used to measure it also collect some other metrics that can be useful to aide optimization like cache misses and branch mispredictions.

#### Memory

Memory usage is another interesting metric, there are different ways of measuring memory but the most useful for us is peak memory, peak memory will many times define if something can even be used in a particular environment. It can also help finding errors related to unusual memory usage.
It is easier to measure, as long as there is enough memory, noise shouldn't affect the results.

#### Hardware utilization

It can be of interest in some cases to measure how much of the available resources are actually used, ideally the same computer will take half the time with twice the resources, unfortunately this isn't always the case and sometimes additional resources go unused.
This doesn't change that often, the main utility of these benchmarks is just to detect low utilization so that it can be improved.
Hardware utilization could include many things, GPU acceleration for example if we were to start using it, but for now will only include CPU/core utilization.

### Layers

There are 3 main layers of the stack that we want to consider, kimchi, snarky and pickles. Given that they are implemented in different languages and exist in different repositories special considerations each layer will be required.

## Where to run the benchmarks

To start everyone with the resources should be able to run the benchmarks locally, additionally we may want some of the benchmarks to run in CI to detect regressions. Some benchmarks may be considerably expensive to run, a decision will have to be made about which benchmarks to run and how often we should run them.

## Parameters

We may be interested in parameterizing some benchmark, for example benchmarking verification time but doing it with different circuits sizes, that would show how performance scales with the size of the circuit.
The introduction of parameters doesn't cause any fundamental change to the benchmarks, but it can considerably increase the cost of running them, making them more the kind of benchmarks that we may not want to run every single time in CI.

## Benchmarks

Next the classes of benchmarks to consider, they are different combinations of metrics, layers and consumers.
  
| benchmarks               | repository    | metric   | for external use | for internal use | regression test | noise sensitive  |
| ------------------------ | ------------- | -------- | ---------------- | ---------------- | --------------- | ---------------- |
| kimchi time              | proof-systems | time     | yes              | yes              | yes             | yes              |
| kimchi time flamegraph   | proof-systems | time     | no               | yes              | no              | no               |
| kimchi instructions      | proof-systems | time     | no               | yes              | yes             | no               |
| kimchi memory            | proof-systems | memory   | yes              | yes              | yes             | no               |
| kimchi memory flamegraph | proof-systems | memory   | no               | yes              | no              | no               |
| snarky time              | mina/snarky*  | time     | yes              | yes              | yes             | yes              |
| snarky memory            | mina/snarky*  | memory   | yes              | yes              | yes             | no               |
| pickles time             | mina/pickles* | time     | yes              | yes              | yes             | yes              |
| pickles memory           | mina/pickles* | memory   | yes              | yes              | yes             | no               |

\* these have to be in Mina now because pickles is in Mina, and while snarky has it's repo, to use it requires a few things still in Mina, if it were possible change that it would make these benchmarks easier and probably cheaper.

### Kimchi time

One of the simplest measuring running time, can be an specific case or allow more flexibility by introducing parameters like for example different circuit sizes. We already have most of the infrastructure for this with criterion. Would ideally have a dedicated computer, considering that there aren't that many PRs in proof-systems the requirements shouldn't be that high.

### Kimchi time flamegraph

This can be considered a variant of the previous, some more research is required but ideally can be generated from the already existing benchmarks with little to no changes.
This may not be as interesting to have in CI, but can be useful to run locally for those working in optimizations.

### Kimchi instructions

This is basically counting the CPU instructions that takes to run some code, could be use as an alternative for CI given that it won't be affected by noise and can work in any computer. It would also be faster by running the code only once. The implementation will require a bit more research but one option is the crate iai, with some thinking it could be possible to have this and the time benchmarks share the same code.
Is worth mentioning that the result are specific to the code and even the computer running the benchmark and thus not useful for comparisons with other projects.

### Kimchi memory

Similar to time, but with memory, the constraints are different in some ways, noise is not generally a problem and any computer cab be used, and also requires less sampling and should run faster. This is to some degree already implemented through a custom measurement for criterion, and in practice can be slower than measuring time, the instrumentation makes it run slower and the some limitations in criterion require to run the code more than necessary. With that in mind the best would be to run just a subset of these benchmark for regressions and let the others be run at discretion.

### Kimchi memory flamegraph

Similar to the time flamegraph, ideally can be made from the memory benchmark without much additional work.

### Snarky time

This is similar to kimchi time, but the fact that it will be in the mina repo should be considered, CI will run much more often and costs may be higher, this would be a reason to prefer to have benchmarks in kimchi when possible.

### Snarky memory

Here the main interest may be regressions, everything else can probably done at the kimchi level more precisely.

### Pickles time

This is similar to snarky time, mostly differing in the overhead of the recursion. At this level beyond some regression we will probably have mostly application circuits being benchmarked.

### Pickles memory

Similar to snarky, this will probably be mostly regression tests and maybe some example application to give users an idea of what to expect.

## Benchmarks

Here is a non exhaustive list of benchmarks.

### Kimchi hash chain

Benchmarking different aspects of a circuit proving a hash chain.

- The length of the hash chain can easily be a parameter allowing to measure different lengths. 
- We want memory and time for compilation, proving and verification, it will be implemented as several benchmarks but they will share most code.
- The number of constraints can be easily shown for each length.
- This benchmark with some specific length can be used as regression tests in CI.
- The full benchmark with several lengths can be shown at discretion of those interested running locally, or even added as optional to CI with some way to trigger it.

### Pickles hash chain

Same as kimchi hash chain but in pickles, we have less to cover here because we already have the kimchi ones, some time and memory benchmarks could be used for regressions and to observe the overhead, but having parameters like different circuits sizes may be redundant.
A new benchmark possible would be to have an alternative circuit that uses recursion to make the hash chain instead of a single circuit, it could be interesting to have a comparison to the non recursive approach.

### General kimchi benchmarks

Some general benchmarks covering compilation, proving and verifying, both time and memory. Ideally all of them will parameterized with different circuit sizes and a subset can be used as regression tests. We could also add here benchmarks for the different operations of our polynomial commitments scheme.
