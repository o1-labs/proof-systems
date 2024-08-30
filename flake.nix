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
      in
      {
        defaultPackage = naersk-lib.buildPackage ./.;
        devShell = with pkgs; mkShell {
          buildInputs = [
            # rust inputs
            rustup
            rust-analyzer
            libiconv # Needed for macOS for rustup

            # ocaml inputs
            opam

            # go inputs
            gopls
            go
            
          ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}