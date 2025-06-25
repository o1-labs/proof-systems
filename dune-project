(lang dune 3.0)

(generate_opam_files true)

(source (github o1-labs/profo-systems))
(license Apache-2.0)
(authors "O(1) Labs, LLC <opensource@o1labs.org>")
(maintainers "O(1) Labs, LLC <opensource@o1labs.org>")
(bug_reports "https://github.com/o1-labs/proof-systems/issues")
(homepage "https://github.com/o1-labs/proof-systems/")

(package
 (name kimchi_types)
 (synopsis "OCaml bindings to types defined in Kimchi")
 (depends
  (dune (>= 3.0))
  (conf-rust (>= 0.1))
 )
)

(package
 (name kimchi_bindings)
 (synopsis "OCaml bindings to Kimchi")
 (depends
  (dune (>= 3.0))
  (conf-rust (>= 0.1))
 )
)

(package
 (name pasta_bindings)
 (synopsis "OCaml bindings to the Pasta curves")
 (depends
  (dune (>= 3.0))
  (conf-rust (>= 0.1))
 )
)
