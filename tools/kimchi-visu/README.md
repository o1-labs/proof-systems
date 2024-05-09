# Kimchi-visu

This is a tool made to help visualize a circuit as an HTML table.

To use it, simply call the [visu] function with an optional witness:

```rust
kimchi_visu::visu(&index, Some(witness));
```

You can reuse the implementation in [src/main.rs](src/main.rs) and call it as:

```console
$ cargo run --bin kimchi-visu
```

The SRS is supposed to be in the parent directory. Create a symlink if you encounter SRS loading issue:
```
ln -s $(pwd)/../../srs $(pwd)/../srs
```
