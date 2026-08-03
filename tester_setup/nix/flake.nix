{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      commonDeps = with pkgs; [
        cmake
        ninja
        ccache
        mold
        clang
        gnumake
        pkg-config
        flex
        bison
        clang-tools
        cppcheck
        valgrind
      ];

      # Library dependencies
      libDeps = with pkgs; [
        libpcap
        doctest
        reproc
        nlohmann_json
        argparse
        nlohmann_json_schema_validator
        openssl
        libnl
        libnl.dev
        libssh
        yaml-cpp
        libtins
        dbus
        zlib
        boost
      ];

      # Tools
      tools = with pkgs; [
        iproute2
        iw
        hostapd-mana
        netsniff-ng
        tcpdump
        wireshark-cli
        gnuplot
        hcxtools
        git
        bmaptool
      ];

    in {
      # Development shell
      devShells.${system}.default = pkgs.mkShell {
        name = "wpa3-tester-env";

        packages = commonDeps ++ libDeps ++ tools;

        shellHook = ''
          export PKG_CONFIG_PATH="${pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" (libDeps ++ [pkgs.stdenv.cc.cc])}:$PKG_CONFIG_PATH"
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath (libDeps ++ [pkgs.stdenv.cc.cc])}:$LD_LIBRARY_PATH"
          export CMAKE_PREFIX_PATH="${pkgs.lib.makeSearchPath "" (libDeps ++ commonDeps ++ [pkgs.stdenv.cc.cc])}:$CMAKE_PREFIX_PATH"
          export CC="clang"
          export CXX="clang++"
        '';
      };
    };
}
