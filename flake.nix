{
  description = "IMAP & SMTP proxy for multi-factor authentication";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    devshell = {
      url = "github:numtide/devshell";
      inputs = {
        flake-utils.follows = "flake-utils";
        nixpkgs.follows = "nixpkgs";
      };
    };
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };
  outputs = { self, nixpkgs, devshell, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) devshell.overlay ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShells = rec {
          default = mfproxy;
          mfproxy = pkgs.devshell.mkShell {
            name = "MFProxy";
            imports = [ "${devshell}/extra/language/c.nix" ];
            packages = with pkgs; [
              (rust-bin.stable.latest.default.override { extensions = [ "rls" "rust-src" ]; })
              cargo-watch
              nixpkgs-fmt
            ];
            env = [
              { name = "RUSTFLAGS"; value = "-D warnings"; }
            ];
            language.c = {
              compiler = pkgs.gcc;
              includes = [ pkgs.openssl ];
              libraries = [ pkgs.openssl ];
            };
          };
        };
      });
}
