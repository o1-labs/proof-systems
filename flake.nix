{
  description = "A flake for O1 labs proof-systems";

  inputs = {
    utils.url = "github:gytis-ivaskevicius/flake-utils-plus";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable-small";
  };

  outputs = inputs@{ self, nixpkgs, utils, ... }:

    utils.lib.eachDefaultSystem
      (system:

        let
          pkgs = nixpkgs.legacyPackages.${system};
          proof-systems =
            let
              # Mac OS specific dependencies
              darwin_packages = with pkgs;
                [
                  curl
                  darwin.apple_sdk.frameworks.Security
                  darwin.apple_sdk.frameworks.CoreServices
                  libiconv
                ];

              buildInputs = with pkgs;
                [
                  pkg-config
                  openssl
                  cargo
                  rustc
                  rustfmt
                ] ++ lib.optionals stdenv.isDarwin darwin_packages;

            in
            pkgs.rustPlatform.buildRustPackage {
              inherit buildInputs;
              pname = "proof-systems";
              version = "0.1.0";
              cargoLock = {
                lockFile = ./Cargo.lock;
              };
              src = pkgs.lib.cleanSource ./.;
            };
        in

        {
          packages = rec { default = proof-systems; };
          devShell = proof-systems.overrideAttrs (oa: { name = "proof-systems-shell"; buildInputs = oa.buildInputs ++ [ pkgs.cowsay ]; }
          );
          devShells.default = self.devShell.${system};
        });

}
