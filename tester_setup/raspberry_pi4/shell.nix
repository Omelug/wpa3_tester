{ pkgs ? import <nixpkgs> {} }:
let
  cross = pkgs.pkgsCross.aarch64-multiplatform;
in pkgs.mkShell {
  nativeBuildInputs = [
    cross.buildPackages.gcc
    cross.buildPackages.binutils
    pkgs.flex
    pkgs.bison
    pkgs.openssl
    pkgs.elfutils
    pkgs.bc
    pkgs.gnumake
    pkgs.perl
    pkgs.python3
    pkgs.rsync
    pkgs.git
  ];
  shellHook = ''
    export CROSS_COMPILE=aarch64-unknown-linux-gnu-
  '';
}
