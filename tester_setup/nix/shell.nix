{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {} }:

pkgs.mkShell {
  name = "wpa3-tester-env";

  packages = with pkgs; [
    # Build tools
    cmake ninja ccache mold
    git clang gnumake pkg-config flex bison
    
    # Tools
    iproute2 iw hostapd-mana
    netsniff-ng tcpdump wireshark-cli gnuplot hcxtools
    trace-cmd
    bmaptool
    
    # Libraries
    libpcap openssl libnl libnl.dev libssh yaml-cpp libtins dbus zlib boost
    doctest reproc nlohmann_json argparse nlohmann_json_schema_validator
    
    # Development tools
    clang-tools
    cppcheck
    valgrind
  ];

  shellHook = ''
    export PKG_CONFIG_PATH="${pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" (with pkgs; [
      libpcap openssl libnl libnl.dev libssh yaml-cpp libtins dbus zlib
    ])}:$PKG_CONFIG_PATH"
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath (with pkgs; [
      pkgs.stdenv.cc.cc.lib libpcap openssl libnl libssh yaml-cpp libtins zlib
    ])}:$LD_LIBRARY_PATH"
    export CMAKE_PREFIX_PATH="${pkgs.lib.makeSearchPath "" (with pkgs; [
      libpcap openssl libnl libnl.dev libssh yaml-cpp libtins dbus zlib
      doctest reproc nlohmann_json argparse nlohmann_json_schema_validator boost
    ])}:$CMAKE_PREFIX_PATH"
    export CC="clang"
    export CXX="clang++"
  '';
}