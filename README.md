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

You may see some debug messages like

`DEBUG: Rule 'raze__syn__0_15_44' indicated that a canonical reproducible form can be obtained by modifying arguments sha256 = "9ca4b3b69a77cbe1ffc9e198781b7acb0c7365a883670e8f1c1bc66fba79a5c5"`

That's because we have not pinned specific versions/commits.  Which is
ok for the moment.

