{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "wpa3-tester-env";

  packages = with pkgs; [
    cmake ninja ccache mold
    git gcc gnumake pkg-config flex bison
    iproute2 iw hostapd-mana
    netsniff-ng tcpdump wireshark-cli gnuplot
    # libraries required by libraries.cmake via pkg-config
    libpcap openssl libnl libssh yaml-cpp libtins dbus
  ];

  shellHook = ''
    export PKG_CONFIG_PATH="${pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" (with pkgs; [
      libpcap openssl libnl libnl.dev libssh yaml-cpp libtins
    ])}:$PKG_CONFIG_PATH"
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath (with pkgs; [
      stdenv.cc.cc.lib libpcap openssl libnl libssh yaml-cpp libtins zlib
    ])}:$LD_LIBRARY_PATH"
  '';
}
