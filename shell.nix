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
in
pkgs.mkShell {
  buildInputs = with pkgs;
    [
      pkg-config
      openssl
      cargo
      rustc
      rustfmt
    ] ++ lib.optionals stdenv.isDarwin darwin_packages;
}
