# Mina book

This directory holds the code related to documentation and specifications of the proof systems.

It is built with [mdbook](https://rust-lang.github.io/mdBook/), which you can use to serve the page via the following command:

```console
$ # setup
$ cargo install mdbook
$ cargo install mdbook-katex
$ cargo install mdbook-linkcheck
$ # serve the page locally
$ mdbook serve
```

The specifications in the book are dynamically generated. Refer to the [specifications/](specifications/) directory.
