This repository contains various protocol Marlin zk-SNARK implementations for recursive SNARK composition.

Bazel support:

List visible targets:

`$ bazel query 'attr(visibility, "//visibility:public", //...:all)' | sort`

You can ignore the `//cargo` and `//bzl` targets. `//:verbose` is a
command line switch, to use it pass `--//:verbose`.

Bazel supports CLI completion, so you can type e.g. `$ bazel build
circuits` and whale on the tab key until you find a target (targets
will always involve ':' after the dir name).

Build a target: three equivalent commands:

* `$ bazel build oracle`
* `$ bazel build //oracle`
* `$ bazel build //oracle:oracle`

Build all: `$ bazel build //...`.  For more options see [Specifying targets to build](https://docs.bazel.build/versions/master/guide.html#specifying-targets-to-build)

NOTE: you may see the following error message. It does not seem to prevent a successful build.

```
INFO: From CargoBuildScriptRun external/raze__crossbeam_utils__0_7_2/crossbeam_utils_build_script.out_dir:
error[E0658]: use of unstable library feature 'integer_atomics'
 --> <anon>:1:18
  |
1 | pub type Probe = core::sync::atomic::AtomicU128;
  |                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |
  = note: see issue #32976 <https://github.com/rust-lang/rust/issues/32976> for more information

error: aborting due to previous error
```

## maintenance

Use [cargo-raze](https://github.com/google/cargo-raze) to manage Bazel support.

To update:

* edit `cargo/Cargo.toml`
* from within `cargo/` run `$ cargo raze`
* test the build
* to pin versions, from within `cargo` run `$ cargo generate-lockfile`
* commit changes to git

