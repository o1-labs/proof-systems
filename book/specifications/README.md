# Specifications

The `specifications/` directory hosts specifications-related code:

* [poly-commitment/](poly-commitment/) contains the specification for the polynomial commitment scheme
* [kimchi/](kimchi/) contains the specification for the proof system

The specifications are written using [cargo-spec](https://crates.io/crates/cargo-spec), which combines markdown files as well as text extracted directly from the code.

## Set up

Install cargo-spec:

```console
$ cargo install cargo-spec
```

## Render

To produce a specification, simply run the following command:

```console
$ make -C <spec_folder> build
```

If you want to watch for any changes, you can also run the following command:

```console
$ make -C <spec_folder> watch
```

## How to edit the specifications

Each folder has the following files:

* a `Specification.toml` file that lists some metadata, the path to a template file, and a list of files to parse for the specification.
* a `template.md` template, which is used as the main specification. Some placeholders will be replaced with information parsed from the code.

Each file listed in the `Specification.toml` have special comments (`//~`) that will be extracted verbatim, and placed within the template.

The idea is to keep as much of the specification close to the source, so that modification of the code and the spec can be done in the same place.

## How to edit the deployment

The specifications are built into the Mina book, and deployed to Github pages, via [this Github Action](/.github/workflows/website.yml).

The Github Action ensures that the generated specifications that are pushed to the remote repository are also up to date.
