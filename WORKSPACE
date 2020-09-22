load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# local_repository(
#     name = "io_bazel_rules_rust",
#     path = "/Users/gar/bazel/rules_rust"
# )

http_archive(
    name = "bazel_skylib",
    urls = [
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
    ],
    sha256 = "1c531376ac7e5a180e0237938a2536de0c54d93f5c278634818e0efc952dd56c",
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
bazel_skylib_workspace()

################################################################
################  RUST  ################

# Minimum rust version: 1.46.0 (?)

# use this until cfg_flags support is upstreamed:
# git_repository(
#     name = "io_bazel_rules_rust",
#     remote = "https://github.com/mobileink/rules_rust.git",
#     # branch = "cfg_flags",
#     commit = "7fda95cff7ea44b97417e2abd344768fed6c0daa",
#     shallow_since = "1590675478 -0500",
# )

http_archive(
    name = "io_bazel_rules_rust",
    # sha256 = "b6da34e057a31b8a85e343c732de4af92a762f804fc36b0baa6c001423a70ebc",
    strip_prefix = "rules_rust-50f45841dc68f7355113ada4d61fecabb528b38f",
    urls = [
        "https://github.com/bazelbuild/rules_rust/archive/50f45841dc68f7355113ada4d61fecabb528b38f.tar.gz",
        # Master branch as of 2019-10-07
        # strip_prefix = "rules_rust-55f77017a7f5b08e525ebeab6e11d8896a4499d2",
        # "https://github.com/bazelbuild/rules_rust/archive/55f77017a7f5b08e525ebeab6e11d8896a4499d2.tar.gz",
    ],
)

load("@io_bazel_rules_rust//rust:repositories.bzl",
     "rust_repositories", "rust_repository_set")
#rust_repositories()
rust_repositories(version = "1.43.1", edition="2018")

load("@io_bazel_rules_rust//:workspace.bzl", "bazel_version")
bazel_version(name = "bazel_version")


####

# load("@io_bazel_rules_rust//:workspace.bzl", "bazel_version")
# bazel_version(name = "bazel_version")

# load("@io_bazel_rules_rust//rust:repositories.bzl",
#      "rust_repositories", "rust_repository_set")
# rust_repositories(version = "1.43.1")
# to set default edition to 2018:

# rust_repository_set(name = "coda_rust_toolchain",
#                     exec_triple = "x86_64-apple-darwin",
#                     # "x86_64-unknown-linux-gnu"
#                     edition = "2018",
#                     version = "1.43.1")


# load("@io_bazel_rules_rust//:workspace.bzl", "bazel_version")
# bazel_version(name = "bazel_version")

################################################################
#### OCAML BAZEL RULES ####
# git_repository(
#     name = "obazl_rules_ocaml",
#     remote = "https://github.com/obazl/rules_ocaml",
#     branch = "master",
#     # commit = "feef897197b36b14b65ffdf00b9badcbdb8f42f4",
#     # shallow_since = "1593623637 -0500"
# )

# load("@obazl_rules_ocaml//ocaml:deps.bzl",
#      "ocaml_configure_tooling",
#      # "ocaml_repositories",
#      # "ocaml_home_sdk",
#      "ocaml_register_toolchains")

# ocaml_configure_tooling()

# ocaml_register_toolchains(installation="host")

http_archive(
    name = "zexe",
    urls = [
        "https://github.com/o1-labs/zexe/archive/610535945f76ceaf5343454d0cc9baeb7295b19a.tar.gz",
        # "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
        # "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.0.3/bazel-skylib-1.0.3.tar.gz",
    ],
    # sha256 = "1c531376ac7e5a180e0237938a2536de0c54d93f5c278634818e0efc952dd56c",
)

# load("//cargo:crates.bzl", "marlin_fetch_remote_crates")
# marlin_fetch_remote_crates()

load("//cargo:crates.bzl", "raze_fetch_remote_crates")
raze_fetch_remote_crates()
