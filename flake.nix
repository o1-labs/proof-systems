{
  description = "proof-system prerequisites";

  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
        ocamlPackages = pkgs.ocaml-ng.ocamlPackages_4_14;
      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;

        devShell = with pkgs; mkShell {
          buildInputs = [
            # rust inputs
            rustup
            rust-analyzer
            libiconv # Needed for macOS for rustup

            # OCaml compiler and core tools
            ocamlPackages.ocaml
            ocamlPackages.findlib
            ocamlPackages.dune_3

            # OCaml development tools
            ocamlPackages.ocaml-lsp
            ocamlPackages.utop
            ocamlPackages.ocamlformat

            # C toolchain needed for FFI
            pkg-config
            gcc

            # go inputs
            gopls
            go

          ];

          # Set environment variables for ocaml-sys
          shellHook = ''
            export OCAMLOPT=${ocamlPackages.ocaml}/bin/ocamlopt
            export OCAML_VERSION=$(${ocamlPackages.ocaml}/bin/ocamlopt -version)
            export OCAML_WHERE_PATH=$(${ocamlPackages.ocaml}/bin/ocamlopt -where)

            export RUST_SRC_PATH="${rustPlatform.rustLibSrc}"

            echo "OCaml version: $OCAML_VERSION"
            echo "OCaml library path: $OCAML_WHERE_PATH"
          '';
        };
      }
    );
}
