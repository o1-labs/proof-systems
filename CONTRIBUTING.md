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
