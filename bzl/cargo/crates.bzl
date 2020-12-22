"""
@generated
cargo-raze generated Bazel file.

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
        url = "https://crates.io/api/v1/crates/alga/0.9.3/download",
        type = "tar.gz",
        sha256 = "4f823d037a7ec6ea2197046bafd4ae150e6bc36f9ca347404f46a46823fa84f2",
        strip_prefix = "alga-0.9.3",
        build_file = Label("//bzl/cargo/remote:BUILD.alga-0.9.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__approx__0_3_2",
        url = "https://crates.io/api/v1/crates/approx/0.3.2/download",
        type = "tar.gz",
        sha256 = "f0e60b75072ecd4168020818c0107f2857bb6c4e64252d8d3983f6263b40a5c3",
        strip_prefix = "approx-0.3.2",
        build_file = Label("//bzl/cargo/remote:BUILD.approx-0.3.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__array_init__0_1_1",
        url = "https://crates.io/api/v1/crates/array-init/0.1.1/download",
        type = "tar.gz",
        sha256 = "f30bbe2f5e3d117f55bd8c7a1f9191e4a5deba9f15f595bbea4f670c59c765db",
        strip_prefix = "array-init-0.1.1",
        build_file = Label("//bzl/cargo/remote:BUILD.array-init-0.1.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__atty__0_2_14",
        url = "https://crates.io/api/v1/crates/atty/0.2.14/download",
        type = "tar.gz",
        sha256 = "d9b39be18770d11421cdb1b9947a45dd3f37e93092cbf377614828a319d5fee8",
        strip_prefix = "atty-0.2.14",
        build_file = Label("//bzl/cargo/remote:BUILD.atty-0.2.14.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__autocfg__1_0_1",
        url = "https://crates.io/api/v1/crates/autocfg/1.0.1/download",
        type = "tar.gz",
        sha256 = "cdb031dd78e28731d87d56cc8ffef4a8f36ca26c38fe2de700543e627f8a464a",
        strip_prefix = "autocfg-1.0.1",
        build_file = Label("//bzl/cargo/remote:BUILD.autocfg-1.0.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__blake2__0_7_1",
        url = "https://crates.io/api/v1/crates/blake2/0.7.1/download",
        type = "tar.gz",
        sha256 = "73b77e29dbd0115e43938be2d5128ecf81c0353e00acaa65339a1242586951d9",
        strip_prefix = "blake2-0.7.1",
        build_file = Label("//bzl/cargo/remote:BUILD.blake2-0.7.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__byte_tools__0_2_0",
        url = "https://crates.io/api/v1/crates/byte-tools/0.2.0/download",
        type = "tar.gz",
        sha256 = "560c32574a12a89ecd91f5e742165893f86e3ab98d21f8ea548658eb9eef5f40",
        strip_prefix = "byte-tools-0.2.0",
        build_file = Label("//bzl/cargo/remote:BUILD.byte-tools-0.2.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__cfg_if__0_1_10",
        url = "https://crates.io/api/v1/crates/cfg-if/0.1.10/download",
        type = "tar.gz",
        sha256 = "4785bdd1c96b2a846b2bd7cc02e86b6b3dbf14e7e53446c4f54c92a361040822",
        strip_prefix = "cfg-if-0.1.10",
        build_file = Label("//bzl/cargo/remote:BUILD.cfg-if-0.1.10.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__cfg_if__1_0_0",
        url = "https://crates.io/api/v1/crates/cfg-if/1.0.0/download",
        type = "tar.gz",
        sha256 = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd",
        strip_prefix = "cfg-if-1.0.0",
        build_file = Label("//bzl/cargo/remote:BUILD.cfg-if-1.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__colored__1_9_3",
        url = "https://crates.io/api/v1/crates/colored/1.9.3/download",
        type = "tar.gz",
        sha256 = "f4ffc801dacf156c5854b9df4f425a626539c3a6ef7893cc0c5084a23f0b6c59",
        strip_prefix = "colored-1.9.3",
        build_file = Label("//bzl/cargo/remote:BUILD.colored-1.9.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__const_fn__0_4_4",
        url = "https://crates.io/api/v1/crates/const_fn/0.4.4/download",
        type = "tar.gz",
        sha256 = "cd51eab21ab4fd6a3bf889e2d0958c0a6e3a61ad04260325e919e652a2a62826",
        strip_prefix = "const_fn-0.4.4",
        build_file = Label("//bzl/cargo/remote:BUILD.const_fn-0.4.4.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__constant_time_eq__0_1_5",
        url = "https://crates.io/api/v1/crates/constant_time_eq/0.1.5/download",
        type = "tar.gz",
        sha256 = "245097e9a4535ee1e3e3931fcfcd55a796a44c643e8596ff6566d68f09b87bbc",
        strip_prefix = "constant_time_eq-0.1.5",
        build_file = Label("//bzl/cargo/remote:BUILD.constant_time_eq-0.1.5.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_channel__0_5_0",
        url = "https://crates.io/api/v1/crates/crossbeam-channel/0.5.0/download",
        type = "tar.gz",
        sha256 = "dca26ee1f8d361640700bde38b2c37d8c22b3ce2d360e1fc1c74ea4b0aa7d775",
        strip_prefix = "crossbeam-channel-0.5.0",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-channel-0.5.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_deque__0_7_3",
        url = "https://crates.io/api/v1/crates/crossbeam-deque/0.7.3/download",
        type = "tar.gz",
        sha256 = "9f02af974daeee82218205558e51ec8768b48cf524bd01d550abe5573a608285",
        strip_prefix = "crossbeam-deque-0.7.3",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-deque-0.7.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_deque__0_8_0",
        url = "https://crates.io/api/v1/crates/crossbeam-deque/0.8.0/download",
        type = "tar.gz",
        sha256 = "94af6efb46fef72616855b036a624cf27ba656ffc9be1b9a3c931cfc7749a9a9",
        strip_prefix = "crossbeam-deque-0.8.0",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-deque-0.8.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_epoch__0_8_2",
        url = "https://crates.io/api/v1/crates/crossbeam-epoch/0.8.2/download",
        type = "tar.gz",
        sha256 = "058ed274caafc1f60c4997b5fc07bf7dc7cca454af7c6e81edffe5f33f70dace",
        strip_prefix = "crossbeam-epoch-0.8.2",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-epoch-0.8.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_epoch__0_9_1",
        url = "https://crates.io/api/v1/crates/crossbeam-epoch/0.9.1/download",
        type = "tar.gz",
        sha256 = "a1aaa739f95311c2c7887a76863f500026092fb1dce0161dab577e559ef3569d",
        strip_prefix = "crossbeam-epoch-0.9.1",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-epoch-0.9.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_utils__0_7_2",
        url = "https://crates.io/api/v1/crates/crossbeam-utils/0.7.2/download",
        type = "tar.gz",
        sha256 = "c3c7c73a2d1e9fc0886a08b93e98eb643461230d5f1925e4036204d5f2e261a8",
        strip_prefix = "crossbeam-utils-0.7.2",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-utils-0.7.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crossbeam_utils__0_8_1",
        url = "https://crates.io/api/v1/crates/crossbeam-utils/0.8.1/download",
        type = "tar.gz",
        sha256 = "02d96d1e189ef58269ebe5b97953da3274d83a93af647c2ddd6f9dab28cedb8d",
        strip_prefix = "crossbeam-utils-0.8.1",
        build_file = Label("//bzl/cargo/remote:BUILD.crossbeam-utils-0.8.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__crypto_mac__0_5_2",
        url = "https://crates.io/api/v1/crates/crypto-mac/0.5.2/download",
        type = "tar.gz",
        sha256 = "0999b4ff4d3446d4ddb19a63e9e00c1876e75cd7000d20e57a693b4b3f08d958",
        strip_prefix = "crypto-mac-0.5.2",
        build_file = Label("//bzl/cargo/remote:BUILD.crypto-mac-0.5.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__cty__0_2_1",
        url = "https://crates.io/api/v1/crates/cty/0.2.1/download",
        type = "tar.gz",
        sha256 = "7313c0d620d0cb4dbd9d019e461a4beb501071ff46ec0ab933efb4daa76d73e3",
        strip_prefix = "cty-0.2.1",
        build_file = Label("//bzl/cargo/remote:BUILD.cty-0.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__digest__0_7_6",
        url = "https://crates.io/api/v1/crates/digest/0.7.6/download",
        type = "tar.gz",
        sha256 = "03b072242a8cbaf9c145665af9d250c59af3b958f83ed6824e13533cf76d5b90",
        strip_prefix = "digest-0.7.6",
        build_file = Label("//bzl/cargo/remote:BUILD.digest-0.7.6.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__either__1_6_1",
        url = "https://crates.io/api/v1/crates/either/1.6.1/download",
        type = "tar.gz",
        sha256 = "e78d4f1cc4ae33bbfc157ed5d5a5ef3bc29227303d595861deb238fcec4e9457",
        strip_prefix = "either-1.6.1",
        build_file = Label("//bzl/cargo/remote:BUILD.either-1.6.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__generic_array__0_9_0",
        url = "https://crates.io/api/v1/crates/generic-array/0.9.0/download",
        type = "tar.gz",
        sha256 = "ef25c5683767570c2bbd7deba372926a55eaae9982d7726ee2a1050239d45b9d",
        strip_prefix = "generic-array-0.9.0",
        build_file = Label("//bzl/cargo/remote:BUILD.generic-array-0.9.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__getrandom__0_1_15",
        url = "https://crates.io/api/v1/crates/getrandom/0.1.15/download",
        type = "tar.gz",
        sha256 = "fc587bc0ec293155d5bfa6b9891ec18a1e330c234f896ea47fbada4cadbe47e6",
        strip_prefix = "getrandom-0.1.15",
        build_file = Label("//bzl/cargo/remote:BUILD.getrandom-0.1.15.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__hermit_abi__0_1_17",
        url = "https://crates.io/api/v1/crates/hermit-abi/0.1.17/download",
        type = "tar.gz",
        sha256 = "5aca5565f760fb5b220e499d72710ed156fdb74e631659e99377d9ebfbd13ae8",
        strip_prefix = "hermit-abi-0.1.17",
        build_file = Label("//bzl/cargo/remote:BUILD.hermit-abi-0.1.17.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__itertools__0_8_2",
        url = "https://crates.io/api/v1/crates/itertools/0.8.2/download",
        type = "tar.gz",
        sha256 = "f56a2d0bc861f9165be4eb3442afd3c236d8a98afd426f65d92324ae1091a484",
        strip_prefix = "itertools-0.8.2",
        build_file = Label("//bzl/cargo/remote:BUILD.itertools-0.8.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__lazy_static__1_4_0",
        url = "https://crates.io/api/v1/crates/lazy_static/1.4.0/download",
        type = "tar.gz",
        sha256 = "e2abad23fbc42b3700f2f279844dc832adb2b2eb069b2df918f455c4e18cc646",
        strip_prefix = "lazy_static-1.4.0",
        build_file = Label("//bzl/cargo/remote:BUILD.lazy_static-1.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__libc__0_2_81",
        url = "https://crates.io/api/v1/crates/libc/0.2.81/download",
        type = "tar.gz",
        sha256 = "1482821306169ec4d07f6aca392a4681f66c75c9918aa49641a2595db64053cb",
        strip_prefix = "libc-0.2.81",
        build_file = Label("//bzl/cargo/remote:BUILD.libc-0.2.81.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__libm__0_2_1",
        url = "https://crates.io/api/v1/crates/libm/0.2.1/download",
        type = "tar.gz",
        sha256 = "c7d73b3f436185384286bd8098d17ec07c9a7d2388a6599f824d8502b529702a",
        strip_prefix = "libm-0.2.1",
        build_file = Label("//bzl/cargo/remote:BUILD.libm-0.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__matrixmultiply__0_2_4",
        url = "https://crates.io/api/v1/crates/matrixmultiply/0.2.4/download",
        type = "tar.gz",
        sha256 = "916806ba0031cd542105d916a97c8572e1fa6dd79c9c51e7eb43a09ec2dd84c1",
        strip_prefix = "matrixmultiply-0.2.4",
        build_file = Label("//bzl/cargo/remote:BUILD.matrixmultiply-0.2.4.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__maybe_uninit__2_0_0",
        url = "https://crates.io/api/v1/crates/maybe-uninit/2.0.0/download",
        type = "tar.gz",
        sha256 = "60302e4db3a61da70c0cb7991976248362f30319e88850c487b9b95bbf059e00",
        strip_prefix = "maybe-uninit-2.0.0",
        build_file = Label("//bzl/cargo/remote:BUILD.maybe-uninit-2.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__memoffset__0_5_6",
        url = "https://crates.io/api/v1/crates/memoffset/0.5.6/download",
        type = "tar.gz",
        sha256 = "043175f069eda7b85febe4a74abbaeff828d9f8b448515d3151a14a3542811aa",
        strip_prefix = "memoffset-0.5.6",
        build_file = Label("//bzl/cargo/remote:BUILD.memoffset-0.5.6.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__memoffset__0_6_1",
        url = "https://crates.io/api/v1/crates/memoffset/0.6.1/download",
        type = "tar.gz",
        sha256 = "157b4208e3059a8f9e78d559edc658e13df41410cb3ae03979c83130067fdd87",
        strip_prefix = "memoffset-0.6.1",
        build_file = Label("//bzl/cargo/remote:BUILD.memoffset-0.6.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ndarray__0_13_1",
        url = "https://crates.io/api/v1/crates/ndarray/0.13.1/download",
        type = "tar.gz",
        sha256 = "ac06db03ec2f46ee0ecdca1a1c34a99c0d188a0d83439b84bf0cb4b386e4ab09",
        strip_prefix = "ndarray-0.13.1",
        build_file = Label("//bzl/cargo/remote:BUILD.ndarray-0.13.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_complex__0_2_4",
        url = "https://crates.io/api/v1/crates/num-complex/0.2.4/download",
        type = "tar.gz",
        sha256 = "b6b19411a9719e753aff12e5187b74d60d3dc449ec3f4dc21e3989c3f554bc95",
        strip_prefix = "num-complex-0.2.4",
        build_file = Label("//bzl/cargo/remote:BUILD.num-complex-0.2.4.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_derive__0_3_3",
        url = "https://crates.io/api/v1/crates/num-derive/0.3.3/download",
        type = "tar.gz",
        sha256 = "876a53fff98e03a936a674b29568b0e605f06b29372c2489ff4de23f1949743d",
        strip_prefix = "num-derive-0.3.3",
        build_file = Label("//bzl/cargo/remote:BUILD.num-derive-0.3.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_integer__0_1_43",
        url = "https://crates.io/api/v1/crates/num-integer/0.1.43/download",
        type = "tar.gz",
        sha256 = "8d59457e662d541ba17869cf51cf177c0b5f0cbf476c66bdc90bf1edac4f875b",
        strip_prefix = "num-integer-0.1.43",
        build_file = Label("//bzl/cargo/remote:BUILD.num-integer-0.1.43.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_traits__0_1_43",
        url = "https://crates.io/api/v1/crates/num-traits/0.1.43/download",
        type = "tar.gz",
        sha256 = "92e5113e9fd4cc14ded8e499429f396a20f98c772a47cc8622a736e1ec843c31",
        strip_prefix = "num-traits-0.1.43",
        build_file = Label("//bzl/cargo/remote:BUILD.num-traits-0.1.43.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_traits__0_2_14",
        url = "https://crates.io/api/v1/crates/num-traits/0.2.14/download",
        type = "tar.gz",
        sha256 = "9a64b1ec5cda2586e284722486d802acf1f7dbdc623e2bfc57e65ca1cd099290",
        strip_prefix = "num-traits-0.2.14",
        build_file = Label("//bzl/cargo/remote:BUILD.num-traits-0.2.14.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__num_cpus__1_13_0",
        url = "https://crates.io/api/v1/crates/num_cpus/1.13.0/download",
        type = "tar.gz",
        sha256 = "05499f3756671c15885fee9034446956fff3f243d6077b91e5767df161f766b3",
        strip_prefix = "num_cpus-1.13.0",
        build_file = Label("//bzl/cargo/remote:BUILD.num_cpus-1.13.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ocaml__0_19_0",
        url = "https://crates.io/api/v1/crates/ocaml/0.19.0/download",
        type = "tar.gz",
        sha256 = "98b213b94c86b14286c44c53cf952e3ba1a9f5c1fef50bbdf5e546a8dcaf11d4",
        strip_prefix = "ocaml-0.19.0",
        build_file = Label("//bzl/cargo/remote:BUILD.ocaml-0.19.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ocaml_derive__0_19_0",
        url = "https://crates.io/api/v1/crates/ocaml-derive/0.19.0/download",
        type = "tar.gz",
        sha256 = "21e86bf321d7b2a9012f284a8fbc0f97244edc0e3a7c6402a368e595524504fd",
        strip_prefix = "ocaml-derive-0.19.0",
        build_file = Label("//bzl/cargo/remote:BUILD.ocaml-derive-0.19.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ocaml_sys__0_19_0",
        url = "https://crates.io/api/v1/crates/ocaml-sys/0.19.0/download",
        type = "tar.gz",
        sha256 = "3ebcb40980dce73b49d0dcf5b3a2844a9a28cbe5fa17115fa09f0f7706463d1a",
        strip_prefix = "ocaml-sys-0.19.0",
        build_file = Label("//bzl/cargo/remote:BUILD.ocaml-sys-0.19.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__ppv_lite86__0_2_10",
        url = "https://crates.io/api/v1/crates/ppv-lite86/0.2.10/download",
        type = "tar.gz",
        sha256 = "ac74c624d6b2d21f425f752262f42188365d7b8ff1aff74c82e45136510a4857",
        strip_prefix = "ppv-lite86-0.2.10",
        build_file = Label("//bzl/cargo/remote:BUILD.ppv-lite86-0.2.10.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__proc_macro2__1_0_17",
        url = "https://crates.io/api/v1/crates/proc-macro2/1.0.17/download",
        type = "tar.gz",
        sha256 = "1502d12e458c49a4c9cbff560d0fe0060c252bc29799ed94ca2ed4bb665a0101",
        strip_prefix = "proc-macro2-1.0.17",
        build_file = Label("//bzl/cargo/remote:BUILD.proc-macro2-1.0.17.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__quote__1_0_6",
        url = "https://crates.io/api/v1/crates/quote/1.0.6/download",
        type = "tar.gz",
        sha256 = "54a21852a652ad6f610c9510194f398ff6f8692e334fd1145fed931f7fbe44ea",
        strip_prefix = "quote-1.0.6",
        build_file = Label("//bzl/cargo/remote:BUILD.quote-1.0.6.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand__0_7_3",
        url = "https://crates.io/api/v1/crates/rand/0.7.3/download",
        type = "tar.gz",
        sha256 = "6a6b1679d49b24bbfe0c803429aa1874472f50d9b363131f0e89fc356b544d03",
        strip_prefix = "rand-0.7.3",
        build_file = Label("//bzl/cargo/remote:BUILD.rand-0.7.3.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand_chacha__0_2_2",
        url = "https://crates.io/api/v1/crates/rand_chacha/0.2.2/download",
        type = "tar.gz",
        sha256 = "f4c8ed856279c9737206bf725bf36935d8666ead7aa69b52be55af369d193402",
        strip_prefix = "rand_chacha-0.2.2",
        build_file = Label("//bzl/cargo/remote:BUILD.rand_chacha-0.2.2.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand_core__0_5_1",
        url = "https://crates.io/api/v1/crates/rand_core/0.5.1/download",
        type = "tar.gz",
        sha256 = "90bde5296fc891b0cef12a6d03ddccc162ce7b2aff54160af9338f8d40df6d19",
        strip_prefix = "rand_core-0.5.1",
        build_file = Label("//bzl/cargo/remote:BUILD.rand_core-0.5.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rand_hc__0_2_0",
        url = "https://crates.io/api/v1/crates/rand_hc/0.2.0/download",
        type = "tar.gz",
        sha256 = "ca3129af7b92a17112d59ad498c6f81eaf463253766b90396d39ea7a39d6613c",
        strip_prefix = "rand_hc-0.2.0",
        build_file = Label("//bzl/cargo/remote:BUILD.rand_hc-0.2.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rawpointer__0_2_1",
        url = "https://crates.io/api/v1/crates/rawpointer/0.2.1/download",
        type = "tar.gz",
        sha256 = "60a357793950651c4ed0f3f52338f53b2f809f32d83a07f72909fa13e4c6c1e3",
        strip_prefix = "rawpointer-0.2.1",
        build_file = Label("//bzl/cargo/remote:BUILD.rawpointer-0.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rayon__1_3_1",
        url = "https://crates.io/api/v1/crates/rayon/1.3.1/download",
        type = "tar.gz",
        sha256 = "62f02856753d04e03e26929f820d0a0a337ebe71f849801eea335d464b349080",
        strip_prefix = "rayon-1.3.1",
        build_file = Label("//bzl/cargo/remote:BUILD.rayon-1.3.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__rayon_core__1_9_0",
        url = "https://crates.io/api/v1/crates/rayon-core/1.9.0/download",
        type = "tar.gz",
        sha256 = "9ab346ac5921dc62ffa9f89b7a773907511cdfa5490c572ae9be1be33e8afa4a",
        strip_prefix = "rayon-core-1.9.0",
        build_file = Label("//bzl/cargo/remote:BUILD.rayon-core-1.9.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__scopeguard__1_1_0",
        url = "https://crates.io/api/v1/crates/scopeguard/1.1.0/download",
        type = "tar.gz",
        sha256 = "d29ab0c6d3fc0ee92fe66e2d99f700eab17a8d57d1c1d3b748380fb20baa78cd",
        strip_prefix = "scopeguard-1.1.0",
        build_file = Label("//bzl/cargo/remote:BUILD.scopeguard-1.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__sprs__0_7_1",
        url = "https://crates.io/api/v1/crates/sprs/0.7.1/download",
        type = "tar.gz",
        sha256 = "ec63571489873d4506683915840eeb1bb16b3198ee4894cc6f2fe3013d505e56",
        strip_prefix = "sprs-0.7.1",
        build_file = Label("//bzl/cargo/remote:BUILD.sprs-0.7.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__syn__1_0_41",
        url = "https://crates.io/api/v1/crates/syn/1.0.41/download",
        type = "tar.gz",
        sha256 = "6690e3e9f692504b941dc6c3b188fd28df054f7fb8469ab40680df52fdcc842b",
        strip_prefix = "syn-1.0.41",
        build_file = Label("//bzl/cargo/remote:BUILD.syn-1.0.41.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__synstructure__0_12_4",
        url = "https://crates.io/api/v1/crates/synstructure/0.12.4/download",
        type = "tar.gz",
        sha256 = "b834f2d66f734cb897113e34aaff2f1ab4719ca946f9a7358dba8f8064148701",
        strip_prefix = "synstructure-0.12.4",
        build_file = Label("//bzl/cargo/remote:BUILD.synstructure-0.12.4.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__typenum__1_12_0",
        url = "https://crates.io/api/v1/crates/typenum/1.12.0/download",
        type = "tar.gz",
        sha256 = "373c8a200f9e67a0c95e62a4f52fbf80c23b4381c05a17845531982fa99e6b33",
        strip_prefix = "typenum-1.12.0",
        build_file = Label("//bzl/cargo/remote:BUILD.typenum-1.12.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__unicode_xid__0_2_1",
        url = "https://crates.io/api/v1/crates/unicode-xid/0.2.1/download",
        type = "tar.gz",
        sha256 = "f7fe0bb3479651439c9112f72b6c505038574c9fbb575ed1bf3b797fa39dd564",
        strip_prefix = "unicode-xid-0.2.1",
        build_file = Label("//bzl/cargo/remote:BUILD.unicode-xid-0.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__wasi__0_9_0_wasi_snapshot_preview1",
        url = "https://crates.io/api/v1/crates/wasi/0.9.0+wasi-snapshot-preview1/download",
        type = "tar.gz",
        sha256 = "cccddf32554fecc6acb585f82a32a72e28b48f8c4c1883ddfeeeaa96f7d8e519",
        strip_prefix = "wasi-0.9.0+wasi-snapshot-preview1",
        build_file = Label("//bzl/cargo/remote:BUILD.wasi-0.9.0+wasi-snapshot-preview1.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi__0_3_9",
        url = "https://crates.io/api/v1/crates/winapi/0.3.9/download",
        type = "tar.gz",
        sha256 = "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
        strip_prefix = "winapi-0.3.9",
        build_file = Label("//bzl/cargo/remote:BUILD.winapi-0.3.9.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_i686_pc_windows_gnu__0_4_0",
        url = "https://crates.io/api/v1/crates/winapi-i686-pc-windows-gnu/0.4.0/download",
        type = "tar.gz",
        sha256 = "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6",
        strip_prefix = "winapi-i686-pc-windows-gnu-0.4.0",
        build_file = Label("//bzl/cargo/remote:BUILD.winapi-i686-pc-windows-gnu-0.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "raze__winapi_x86_64_pc_windows_gnu__0_4_0",
        url = "https://crates.io/api/v1/crates/winapi-x86_64-pc-windows-gnu/0.4.0/download",
        type = "tar.gz",
        sha256 = "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f",
        strip_prefix = "winapi-x86_64-pc-windows-gnu-0.4.0",
        build_file = Label("//bzl/cargo/remote:BUILD.winapi-x86_64-pc-windows-gnu-0.4.0.bazel"),
    )
