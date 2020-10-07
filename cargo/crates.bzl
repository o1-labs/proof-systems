"""
@generated
cargo-raze crate workspace functions

DO NOT EDIT! Replaced on runs of cargo-raze
"""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")  # buildifier: disable=load
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")  # buildifier: disable=load
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")  # buildifier: disable=load

def raze_fetch_remote_crates():
    """This function defines a collection of repos and should be called in a WORKSPACE file"""
    maybe(
        http_archive,
        name = "raze__alga__0_9_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/alga/alga-0.9.3.crate",
        type = "tar.gz",
        strip_prefix = "alga-0.9.3",
        build_file = Label("//cargo/remote:alga-0.9.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__approx__0_3_2",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/approx/approx-0.3.2.crate",
        type = "tar.gz",
        strip_prefix = "approx-0.3.2",
        build_file = Label("//cargo/remote:approx-0.3.2.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__array_init__0_1_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/array-init/array-init-0.1.1.crate",
        type = "tar.gz",
        strip_prefix = "array-init-0.1.1",
        build_file = Label("//cargo/remote:array-init-0.1.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__atty__0_2_14",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/atty/atty-0.2.14.crate",
        type = "tar.gz",
        strip_prefix = "atty-0.2.14",
        build_file = Label("//cargo/remote:atty-0.2.14.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__autocfg__0_1_7",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/autocfg/autocfg-0.1.7.crate",
        type = "tar.gz",
        strip_prefix = "autocfg-0.1.7",
        build_file = Label("//cargo/remote:autocfg-0.1.7.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__autocfg__1_0_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/autocfg/autocfg-1.0.1.crate",
        type = "tar.gz",
        strip_prefix = "autocfg-1.0.1",
        build_file = Label("//cargo/remote:autocfg-1.0.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__blake2__0_8_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/blake2/blake2-0.8.1.crate",
        type = "tar.gz",
        strip_prefix = "blake2-0.8.1",
        build_file = Label("//cargo/remote:blake2-0.8.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__byte_tools__0_3_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/byte-tools/byte-tools-0.3.1.crate",
        type = "tar.gz",
        strip_prefix = "byte-tools-0.3.1",
        build_file = Label("//cargo/remote:byte-tools-0.3.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__cfg_if__0_1_10",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/cfg-if/cfg-if-0.1.10.crate",
        type = "tar.gz",
        strip_prefix = "cfg-if-0.1.10",
        build_file = Label("//cargo/remote:cfg-if-0.1.10.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__colored__1_9_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/colored/colored-1.9.3.crate",
        type = "tar.gz",
        strip_prefix = "colored-1.9.3",
        build_file = Label("//cargo/remote:colored-1.9.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_channel__0_4_4",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/crossbeam-channel/crossbeam-channel-0.4.4.crate",
        type = "tar.gz",
        strip_prefix = "crossbeam-channel-0.4.4",
        build_file = Label("//cargo/remote:crossbeam-channel-0.4.4.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_deque__0_7_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/crossbeam-deque/crossbeam-deque-0.7.3.crate",
        type = "tar.gz",
        strip_prefix = "crossbeam-deque-0.7.3",
        build_file = Label("//cargo/remote:crossbeam-deque-0.7.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_epoch__0_8_2",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/crossbeam-epoch/crossbeam-epoch-0.8.2.crate",
        type = "tar.gz",
        strip_prefix = "crossbeam-epoch-0.8.2",
        build_file = Label("//cargo/remote:crossbeam-epoch-0.8.2.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_utils__0_7_2",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/crossbeam-utils/crossbeam-utils-0.7.2.crate",
        type = "tar.gz",
        strip_prefix = "crossbeam-utils-0.7.2",
        build_file = Label("//cargo/remote:crossbeam-utils-0.7.2.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crypto_mac__0_7_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/crypto-mac/crypto-mac-0.7.0.crate",
        type = "tar.gz",
        strip_prefix = "crypto-mac-0.7.0",
        build_file = Label("//cargo/remote:crypto-mac-0.7.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__derivative__2_1_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/derivative/derivative-2.1.1.crate",
        type = "tar.gz",
        strip_prefix = "derivative-2.1.1",
        build_file = Label("//cargo/remote:derivative-2.1.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__digest__0_8_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/digest/digest-0.8.1.crate",
        type = "tar.gz",
        strip_prefix = "digest-0.8.1",
        build_file = Label("//cargo/remote:digest-0.8.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__either__1_6_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/either/either-1.6.1.crate",
        type = "tar.gz",
        strip_prefix = "either-1.6.1",
        build_file = Label("//cargo/remote:either-1.6.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__generic_array__0_12_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/generic-array/generic-array-0.12.3.crate",
        type = "tar.gz",
        strip_prefix = "generic-array-0.12.3",
        build_file = Label("//cargo/remote:generic-array-0.12.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__getrandom__0_1_15",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/getrandom/getrandom-0.1.15.crate",
        type = "tar.gz",
        strip_prefix = "getrandom-0.1.15",
        build_file = Label("//cargo/remote:getrandom-0.1.15.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__hermit_abi__0_1_15",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/hermit-abi/hermit-abi-0.1.15.crate",
        type = "tar.gz",
        strip_prefix = "hermit-abi-0.1.15",
        build_file = Label("//cargo/remote:hermit-abi-0.1.15.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__itertools__0_8_2",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/itertools/itertools-0.8.2.crate",
        type = "tar.gz",
        strip_prefix = "itertools-0.8.2",
        build_file = Label("//cargo/remote:itertools-0.8.2.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__lazy_static__1_4_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/lazy_static/lazy_static-1.4.0.crate",
        type = "tar.gz",
        strip_prefix = "lazy_static-1.4.0",
        build_file = Label("//cargo/remote:lazy_static-1.4.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__libc__0_2_77",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/libc/libc-0.2.77.crate",
        type = "tar.gz",
        strip_prefix = "libc-0.2.77",
        build_file = Label("//cargo/remote:libc-0.2.77.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__libm__0_2_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/libm/libm-0.2.1.crate",
        type = "tar.gz",
        strip_prefix = "libm-0.2.1",
        build_file = Label("//cargo/remote:libm-0.2.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__matrixmultiply__0_2_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/matrixmultiply/matrixmultiply-0.2.3.crate",
        type = "tar.gz",
        strip_prefix = "matrixmultiply-0.2.3",
        build_file = Label("//cargo/remote:matrixmultiply-0.2.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__maybe_uninit__2_0_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/maybe-uninit/maybe-uninit-2.0.0.crate",
        type = "tar.gz",
        strip_prefix = "maybe-uninit-2.0.0",
        build_file = Label("//cargo/remote:maybe-uninit-2.0.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__memoffset__0_5_6",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/memoffset/memoffset-0.5.6.crate",
        type = "tar.gz",
        strip_prefix = "memoffset-0.5.6",
        build_file = Label("//cargo/remote:memoffset-0.5.6.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ndarray__0_13_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/ndarray/ndarray-0.13.1.crate",
        type = "tar.gz",
        strip_prefix = "ndarray-0.13.1",
        build_file = Label("//cargo/remote:ndarray-0.13.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_bigint__0_2_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/num-bigint/num-bigint-0.2.3.crate",
        type = "tar.gz",
        strip_prefix = "num-bigint-0.2.3",
        build_file = Label("//cargo/remote:num-bigint-0.2.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_complex__0_2_4",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/num-complex/num-complex-0.2.4.crate",
        type = "tar.gz",
        strip_prefix = "num-complex-0.2.4",
        build_file = Label("//cargo/remote:num-complex-0.2.4.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_integer__0_1_43",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/num-integer/num-integer-0.1.43.crate",
        type = "tar.gz",
        strip_prefix = "num-integer-0.1.43",
        build_file = Label("//cargo/remote:num-integer-0.1.43.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_traits__0_1_43",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/num-traits/num-traits-0.1.43.crate",
        type = "tar.gz",
        strip_prefix = "num-traits-0.1.43",
        build_file = Label("//cargo/remote:num-traits-0.1.43.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_traits__0_2_11",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/num-traits/num-traits-0.2.11.crate",
        type = "tar.gz",
        strip_prefix = "num-traits-0.2.11",
        build_file = Label("//cargo/remote:num-traits-0.2.11.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_cpus__1_13_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/num_cpus/num_cpus-1.13.0.crate",
        type = "tar.gz",
        strip_prefix = "num_cpus-1.13.0",
        build_file = Label("//cargo/remote:num_cpus-1.13.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__opaque_debug__0_2_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/opaque-debug/opaque-debug-0.2.3.crate",
        type = "tar.gz",
        strip_prefix = "opaque-debug-0.2.3",
        build_file = Label("//cargo/remote:opaque-debug-0.2.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ppv_lite86__0_2_9",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/ppv-lite86/ppv-lite86-0.2.9.crate",
        type = "tar.gz",
        strip_prefix = "ppv-lite86-0.2.9",
        build_file = Label("//cargo/remote:ppv-lite86-0.2.9.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__proc_macro2__0_4_30",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/proc-macro2/proc-macro2-0.4.30.crate",
        type = "tar.gz",
        strip_prefix = "proc-macro2-0.4.30",
        build_file = Label("//cargo/remote:proc-macro2-0.4.30.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__proc_macro2__1_0_17",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/proc-macro2/proc-macro2-1.0.17.crate",
        type = "tar.gz",
        strip_prefix = "proc-macro2-1.0.17",
        build_file = Label("//cargo/remote:proc-macro2-1.0.17.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__quote__0_6_13",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/quote/quote-0.6.13.crate",
        type = "tar.gz",
        strip_prefix = "quote-0.6.13",
        build_file = Label("//cargo/remote:quote-0.6.13.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__quote__1_0_6",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/quote/quote-1.0.6.crate",
        type = "tar.gz",
        strip_prefix = "quote-1.0.6",
        build_file = Label("//cargo/remote:quote-1.0.6.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand__0_7_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rand/rand-0.7.3.crate",
        type = "tar.gz",
        strip_prefix = "rand-0.7.3",
        build_file = Label("//cargo/remote:rand-0.7.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand_chacha__0_2_2",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rand_chacha/rand_chacha-0.2.2.crate",
        type = "tar.gz",
        strip_prefix = "rand_chacha-0.2.2",
        build_file = Label("//cargo/remote:rand_chacha-0.2.2.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand_core__0_5_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rand_core/rand_core-0.5.1.crate",
        type = "tar.gz",
        strip_prefix = "rand_core-0.5.1",
        build_file = Label("//cargo/remote:rand_core-0.5.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand_hc__0_2_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rand_hc/rand_hc-0.2.0.crate",
        type = "tar.gz",
        strip_prefix = "rand_hc-0.2.0",
        build_file = Label("//cargo/remote:rand_hc-0.2.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rawpointer__0_2_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rawpointer/rawpointer-0.2.1.crate",
        type = "tar.gz",
        strip_prefix = "rawpointer-0.2.1",
        build_file = Label("//cargo/remote:rawpointer-0.2.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rayon__1_3_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rayon/rayon-1.3.1.crate",
        type = "tar.gz",
        strip_prefix = "rayon-1.3.1",
        build_file = Label("//cargo/remote:rayon-1.3.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rayon_core__1_8_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rayon-core/rayon-core-1.8.1.crate",
        type = "tar.gz",
        strip_prefix = "rayon-core-1.8.1",
        build_file = Label("//cargo/remote:rayon-core-1.8.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rustc_version__0_2_3",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/rustc_version/rustc_version-0.2.3.crate",
        type = "tar.gz",
        strip_prefix = "rustc_version-0.2.3",
        build_file = Label("//cargo/remote:rustc_version-0.2.3.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__scopeguard__1_1_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/scopeguard/scopeguard-1.1.0.crate",
        type = "tar.gz",
        strip_prefix = "scopeguard-1.1.0",
        build_file = Label("//cargo/remote:scopeguard-1.1.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__semver__0_9_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/semver/semver-0.9.0.crate",
        type = "tar.gz",
        strip_prefix = "semver-0.9.0",
        build_file = Label("//cargo/remote:semver-0.9.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__semver_parser__0_7_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/semver-parser/semver-parser-0.7.0.crate",
        type = "tar.gz",
        strip_prefix = "semver-parser-0.7.0",
        build_file = Label("//cargo/remote:semver-parser-0.7.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__sprs__0_7_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/sprs/sprs-0.7.1.crate",
        type = "tar.gz",
        strip_prefix = "sprs-0.7.1",
        build_file = Label("//cargo/remote:sprs-0.7.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__subtle__1_0_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/subtle/subtle-1.0.0.crate",
        type = "tar.gz",
        strip_prefix = "subtle-1.0.0",
        build_file = Label("//cargo/remote:subtle-1.0.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__syn__0_15_44",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/syn/syn-0.15.44.crate",
        type = "tar.gz",
        strip_prefix = "syn-0.15.44",
        build_file = Label("//cargo/remote:syn-0.15.44.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__syn__1_0_17",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/syn/syn-1.0.17.crate",
        type = "tar.gz",
        strip_prefix = "syn-1.0.17",
        build_file = Label("//cargo/remote:syn-1.0.17.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__typenum__1_12_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/typenum/typenum-1.12.0.crate",
        type = "tar.gz",
        strip_prefix = "typenum-1.12.0",
        build_file = Label("//cargo/remote:typenum-1.12.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__unicode_xid__0_1_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/unicode-xid/unicode-xid-0.1.0.crate",
        type = "tar.gz",
        strip_prefix = "unicode-xid-0.1.0",
        build_file = Label("//cargo/remote:unicode-xid-0.1.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__unicode_xid__0_2_1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/unicode-xid/unicode-xid-0.2.1.crate",
        type = "tar.gz",
        strip_prefix = "unicode-xid-0.2.1",
        build_file = Label("//cargo/remote:unicode-xid-0.2.1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__unroll__0_1_4",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/unroll/unroll-0.1.4.crate",
        type = "tar.gz",
        strip_prefix = "unroll-0.1.4",
        build_file = Label("//cargo/remote:unroll-0.1.4.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__wasi__0_9_0_wasi_snapshot_preview1",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/wasi/wasi-0.9.0+wasi-snapshot-preview1.crate",
        type = "tar.gz",
        strip_prefix = "wasi-0.9.0+wasi-snapshot-preview1",
        build_file = Label("//cargo/remote:wasi-0.9.0+wasi-snapshot-preview1.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi__0_3_9",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/winapi/winapi-0.3.9.crate",
        type = "tar.gz",
        strip_prefix = "winapi-0.3.9",
        build_file = Label("//cargo/remote:winapi-0.3.9.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_i686_pc_windows_gnu__0_4_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/winapi-i686-pc-windows-gnu/winapi-i686-pc-windows-gnu-0.4.0.crate",
        type = "tar.gz",
        strip_prefix = "winapi-i686-pc-windows-gnu-0.4.0",
        build_file = Label("//cargo/remote:winapi-i686-pc-windows-gnu-0.4.0.BUILD.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_x86_64_pc_windows_gnu__0_4_0",
        url = "https://crates-io.s3-us-west-1.amazonaws.com/crates/winapi-x86_64-pc-windows-gnu/winapi-x86_64-pc-windows-gnu-0.4.0.crate",
        type = "tar.gz",
        strip_prefix = "winapi-x86_64-pc-windows-gnu-0.4.0",
        build_file = Label("//cargo/remote:winapi-x86_64-pc-windows-gnu-0.4.0.BUILD.bazel"),
    )
