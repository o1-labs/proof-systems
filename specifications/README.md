# Specifications

This directory holds the specifications of the different algorithms implemented in this repository:

* [poly-commitment/](poly-commitment/) contains the specification for the polynomial commitment scheme
* [kimchi/](kimchi/) contains the specification for the proof system

These specifications are written using [cargo-spec](https://crates.io/crates/cargo-spec), which combines markdown files as well as text extracted directly from the code (comments that start with `//~`).
To produce a specification, simply run the following command:

```console
$ make build
```

The specifications are meant to be consumed through the specification page, which you can serve via the following command:

```console
$ make serve
```

You can also build it via the following one, which is ran as part of a [Github action]() to deploy it as a [Github Page](). See [.github/workflows/](../.github/workflows/gh-pages.yml):

```console
$ ./build.sh
```


## How to edit the specifications

* [Hugo-book](https://github.com/alex-shpak/hugo-book)
* markdown
* specification.toml file
* specification.md template
* each file listed in specification.toml will have `//~` comments that get extracted
