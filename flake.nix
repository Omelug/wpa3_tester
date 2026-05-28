{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: let
    system  = "x86_64-linux";
    pkgs    = nixpkgs.legacyPackages.${system};

    # Paths injected at evaluation time via --impure (set in CI or locally)
    workspace = builtins.getEnv "GITHUB_WORKSPACE";
    srcDir    = if workspace != "" then workspace else toString ./.;
    depsDir   = builtins.getEnv "WPATESTER_DEPS_DIR";

  in {
    checks.${system}.hwsim = pkgs.nixosTest {
      name = "wpa3-hwsim";

      nodes.machine = { pkgs, ... }: {
        boot.kernelModules = [ "mac80211_hwsim" ];

        environment.systemPackages = with pkgs; [
          cmake ninja gcc pkg-config flex bison iw
          libnl libssh libtins openssl yaml-cpp
        ];

        virtualisation.memorySize = 2048;
        virtualisation.diskSize   = 4096;

        virtualisation.sharedDirectories = {
          src  = { source = srcDir;   target = "/src";  };
          deps = { source = depsDir;  target = "/deps"; };
        };
      };

      testScript = ''
        machine.wait_for_unit("multi-user.target")

        # Build only the hwsim test binary; deps already pre-fetched on host
        machine.succeed(
          "cmake -S /src/wpa3_test -B /build -G Ninja"
          " -DFETCHCONTENT_BASE_DIR=/deps"
          " -DFETCHCONTENT_FULLY_DISCONNECTED=ON"
          " 2>&1 | tail -5"
        )
        machine.succeed(
          "cmake --build /build --target run_hwsim_tests -j$(nproc)"
          " 2>&1 | tail -10"
        )

        # Set up hwsim interfaces
        machine.succeed("modprobe mac80211_hwsim radios=2")
        machine.succeed("udevadm settle")
        for iface in machine.succeed("ls /sys/class/net").split():
            if iface.startswith("wlan"):
                machine.succeed(f"ip link set {iface} name hwsim_{iface}")
        machine.succeed("udevadm settle")

        machine.succeed("/build/tests/integration/run_hwsim_tests 2>&1")
      '';
    };
  };
}
