{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {}
, cross    ? false   # nix-shell --arg cross true     → adds aarch64 cross-toolchain
, internet ? false   # nix-shell --arg internet true  → sets eth0=10.0.0.1/24 + NAT to Pi
}:

let
  crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;

  internetHook = ''
    # eth0 static IP — host side of direct notebook↔Pi cable
    if ! ip addr show eth0 2>/dev/null | grep -q "10\.0\.0\.1/24"; then
      sudo ip addr add 10.0.0.1/24 dev eth0 2>/dev/null || true
    fi
    sudo ip link set eth0 up 2>/dev/null || true
    # NAT: share WAN internet to eth0 (mirrors make internet from internet.mk)
    _HOST_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [ -n "$_HOST_IFACE" ] && [ "$_HOST_IFACE" != "eth0" ]; then
      sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
      sudo iptables -t nat -C POSTROUTING -o "$_HOST_IFACE" -j MASQUERADE 2>/dev/null || \
          sudo iptables -t nat -A POSTROUTING -o "$_HOST_IFACE" -j MASQUERADE
      sudo iptables -C FORWARD -i eth0 -o "$_HOST_IFACE" -j ACCEPT 2>/dev/null || \
          sudo iptables -A FORWARD -i eth0 -o "$_HOST_IFACE" -j ACCEPT
      echo "==> eth0: 10.0.0.1/24  internet: $_HOST_IFACE -> eth0  Pi: 10.0.0.2"
    else
      echo "Warning: WAN interface not detected (internet sharing skipped)"
    fi
  '';
in
pkgs.mkShell {
  name = "wpa3-tester${if cross then "-cross-rpi4" else ""}${if internet then "-internet" else ""}";

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
  ] ++ pkgs.lib.optionals cross [
    crossPkgs.buildPackages.gcc
    crossPkgs.buildPackages.binutils
    pkgs.gdb   # multiarch on nixpkgs — debugs aarch64 from x86_64 host
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
    ${pkgs.lib.optionalString cross ''
      echo "aarch64 cross-toolchain ready ($(aarch64-unknown-linux-gnu-gcc --version | head -1))"
    ''}
    ${pkgs.lib.optionalString internet internetHook}
  '';
}
