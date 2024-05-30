let
  pkgs = import <nixpkgs> { config = {}; overlays = []; };
in
pkgs.mkShell {
  packages = with pkgs; [
    pkg-config
    cargo
    #gcc
    openssl
    mdbook-pdf
    chromium # required by mdbook-pdf
  ]
  ;

}
