# Contributing to kimchi

Here's all you need to know to start contributing to kimchi.

## Navigating the project

- [The following video](https://www.youtube.com/watch?v=WUP54nqVedc) goes over the project organization.
- The [Mina book](https://o1-labs.github.io/proof-systems/) contains specifications, rust documentation, RFCs, and explainers on the different aspects of the system.
- The [Discussion page](https://github.com/o1-labs/proof-systems/discussions) can be used to start discussions or ask questions.

## Finding a task

We have a list of easy task to start contributing. [Start over there](https://github.com/o1-labs/proof-systems/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+task+to+start+contributing%22).

## Setting up the project

Make sure you have the GNU `make` utility installed since we use it to streamline various tasks.
Windows users may need to use the `WSL` to run `make` commands.
For the complete list of `make` targets, please refer to the [Makefile](Makefile).

After the repository being cloned, run:

```shell
make setup
```

this will also synchronize the Git submodules to get the version of Optimism the zkVM has been developed for.

### Mac & Linux

- Follow these instructions to install OCaml: <https://ocaml.org/docs/install.html>
- Follow these instructions to install Rust: <https://rustup.rs/>

### Windows Development

Windows development can be done using [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/install).

- Install and open WSL
- Within WSL, install OCaml using your distro's package manager. For example: `apt install opam`
- Within WSL, navigate to the project directory and run `cargo test`. If there are no failures then everything is set up correctly.

## Development

To run all tests:

### Setting up

```shell
make install-test-deps
```

### Cargo test runner

```shell
make test-all
```

### Nextest test runner

```shell
make nextest-all
```

We also provide the `make` targets to run tests with the code coverage reporting, for example:

```shell
make test-all-with-coverage
```

You can also specify an extra CLI argument to `make` to pass it to the cargo or binary, for example:

```shell
CARGO_EXTRA_ARGS="-p poly-commitment" make test-all-with-coverage
BIN_EXTRA_ARGS="-p poly-commitment" make nextest-all-with-coverage
```

Note: In example above we run tests for the `poly-commitment` package only.
You can also use the environment variable `BIN_EXTRA_ARGS` to select a specific
test to run. For instance:
```
BIN_EXTRA_ARGS="test_opening_proof" make nextest
```
will only run the tests containing `test_opening_proof`.

We build and run tests in `--release` mode, because otherwise tests execution can last for a long time.

To check formatting:

```shell
make format
```

To scan for lints:

```shell
make lint
```

Note: cargo can automatically fix some lints. To do so, add `--fix` to the `CARGO_EXTRA_ARGS` variable and use it with the command above like this:

```shell
CARGO_EXTRA_ARGS="--fix" make lint
```

Formatting and lints are enforced by GitHub PR checks, so please be sure to have any errors produced by the above tools fixed before pushing the code to your pull request branch.
Please refer to [CI](.github/workflows/ci.yml) workflow to see all PR checks.

## Branching policy

Generally, proof-systems intends to be synchronized with the mina repository (see their [README-branching.md](https://github.com/MinaProtocol/mina/blob/develop/README-branching.md)), and so its branching policy is quite similar. However several important (some, temporary) distinctions exist:

- `compatible`:
  - Compatible with `rampup` in `mina`.
  - Mina's `compatible`, similarly to mina's `master`, does not have `proof-systems`.
- `berkeley`: future hardfork release, will be going out to berkeley.
  - This is where hotfixes go.
- `develop`: matches mina's `develop`, soft fork-compatibility.
  - Also used by `mina/o1js-main` and `o1js/main`.
- `master`: future feature work development, containing breaking changes. Anything that does not need to be released alongside mina.
  - Note that `mina`'s `master` does not depend on `proof-systems` at all.
- `izmir`: next hardfork release after berkeley.
- In the future:
  - `master`/`develop` will reverse roles and become something like gitflow.
  - After Berkeley release `compatible` will become properly synced with `mina/compatible`.
- Direction of merge:
  - Back-merging: `compatible` into `berkeley` into `develop` into `master`.
  - Front-merging (introducing new features): other direction, but where you start depends on where the feature belongs.
