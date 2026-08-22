{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;

      commonDeps = with pkgs; [
        cmake ninja ccache mold clang gnumake pkg-config flex bison
        clang-tools cppcheck valgrind
      ];

      libDeps = with pkgs; [
        libpcap doctest reproc nlohmann_json argparse nlohmann_json_schema_validator
        openssl libnl libnl.dev libssh yaml-cpp libtins dbus zlib boost
      ];

      tools = with pkgs; [
        iproute2 iw hostapd-mana netsniff-ng tcpdump wireshark-cli
        gnuplot hcxtools git bmaptool trace-cmd
      ];

      crossTools = with pkgs; [
        crossPkgs.buildPackages.gcc
        crossPkgs.buildPackages.binutils
        gdb   # multiarch on nixpkgs — debugs aarch64 from x86_64 host
      ];

      # Mirrors `make internet` from internet.mk + sets eth0=10.0.0.1/24
      internetHook = ''
        if ! ip addr show eth0 2>/dev/null | grep -q "10\.0\.0\.1/24"; then
          sudo ip addr add 10.0.0.1/24 dev eth0 2>/dev/null || true
        fi
        sudo ip link set eth0 up 2>/dev/null || true
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

      baseHook = ''
        export PKG_CONFIG_PATH="${pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" (libDeps ++ [pkgs.stdenv.cc.cc])}:$PKG_CONFIG_PATH"
        export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath (libDeps ++ [pkgs.stdenv.cc.cc])}:$LD_LIBRARY_PATH"
        export CMAKE_PREFIX_PATH="${pkgs.lib.makeSearchPath "" (libDeps ++ commonDeps ++ [pkgs.stdenv.cc.cc])}:$CMAKE_PREFIX_PATH"
        export CC="clang"
        export CXX="clang++"
      '';

      crossHook = ''
        echo "aarch64 cross-toolchain ready ($(aarch64-unknown-linux-gnu-gcc --version | head -1))"
        echo "Next: make sysroot PI=<addr>  then  make deploy-cross PI=<addr>"
      '';

    in {
      devShells.${system} = {
        # nix develop .#default  (or just: nix develop)
        default = pkgs.mkShell {
          name = "wpa3-tester-env";
          packages = commonDeps ++ libDeps ++ tools;
          shellHook = baseHook;
        };

        # nix develop .#cross-rpi4
        cross-rpi4 = pkgs.mkShell {
          name = "wpa3-tester-cross-rpi4";
          packages = commonDeps ++ tools ++ crossTools;
          shellHook = baseHook + crossHook;
        };

        # nix develop .#cross-rpi4-internet
        cross-rpi4-internet = pkgs.mkShell {
          name = "wpa3-tester-cross-rpi4-internet";
          packages = commonDeps ++ tools ++ crossTools;
          shellHook = baseHook + crossHook + internetHook;
        };

        # nix develop .#internet  (native build + internet sharing only)
        internet = pkgs.mkShell {
          name = "wpa3-tester-internet";
          packages = commonDeps ++ libDeps ++ tools;
          shellHook = baseHook + internetHook;
        };
      };
    };
}
