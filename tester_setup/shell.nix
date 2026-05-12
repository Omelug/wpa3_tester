{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "wpa3-tester-env";

  packages = with pkgs; [
    cmake
    git
    gcc
    gnumake
    iproute2   # ip
    iw
    mold #can use ld/lld but its slower
  ];
}
