{ pkgs ? import <nixpkgs> { } }:

let
  # Mac OS specific dependencies
  darwin_packages = (with pkgs;
    [
      curl
      darwin.apple_sdk.frameworks.Security
      darwin.apple_sdk.frameworks.CoreServices
      libiconv
    ]);

  buildInputs = with pkgs;
    [
      pkg-config
      openssl
      cargo
      rustc
      rustfmt
    ] ++ lib.optionals stdenv.isDarwin darwin_packages;

in
{
  proof-systems =
    pkgs.rustPlatform.buildRustPackage
      {
        inherit buildInputs;
        pname = "proof-systems";
        version = "1.0.0";
        cargoLock = {
          lockFile = ./Cargo.lock;
        };
        src = pkgs.lib.cleanSource ./.;
      };

  devshell = pkgs.mkShell {
    inherit buildInputs;
  };
}
