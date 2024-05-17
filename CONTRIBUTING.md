# Contributing to kimchi

Here's all you need to know to start contributing to kimchi.

## Navigating the project

* [The following video](https://www.youtube.com/watch?v=WUP54nqVedc) goes over the project organization.
* The [Mina book](https://o1-labs.github.io/proof-systems/) contains specifications, rust documentation, RFCs, and explainers on the different aspects of the system.
* The [Discussion page](https://github.com/o1-labs/proof-systems/discussions) can be used to start discussions or ask questions.

## Finding a task

We have a list of easy task to start contributing. [Start over there](https://github.com/o1-labs/proof-systems/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+task+to+start+contributing%22).

## Setting up the project

### Mac & Linux

* Follow these instructions to install OCaml: https://ocaml.org/docs/install.html
* Follow these instructions to install Rust: https://rustup.rs/

### Windows Development

Windows development can be done using [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/install).
* Install and open WSL
* Within WSL, install OCaml using your distro's package manager. For example: `apt install opam`
* Within WSL, navigate to the project directory and run `cargo test`. If there are no failures then everything is set up correctly.

## Development

To run tests:
```bash
cargo test --all-features --release
```

Takes about 5-8 minutes on a MacBook Pro (2019, 8-Core Intel Core i9, 32GB RAM). Without `--release`, more than an hour.

To scan for lints:
```bash
cargo clippy --all-features --tests --all-targets -- -D warnings
```

Note: cargo can automatically fix some lints. To do so, add `--fix` to the above command (as the first parameter).

Finally, to check formatting:
```bash
cargo fmt
```

These are enforced by GitHub PR checks, so be sure to have any errors produced by the above tools fixed before pushing the code to your pull request branch. Refer to `.github/workflows` for all PR checks.

## Branching policy

Generally, proof-systems intends to be synchronized with the mina repository (see their [README-branching.md](https://github.com/MinaProtocol/mina/blob/develop/README-branching.md)), and so its branching policy is quite similar. However several important (some, temporary) distinctions exist:

- `compatible`:
    - Compatible with `rampup` in `mina`.
    - Mina's `compatible`, similarly to mina's `master`, does not have `proof-systems`.
- `berkley`: future hardfork release, will be going out to berkeley.
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
