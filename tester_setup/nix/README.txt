

nix-shell tester_setup/nix/shell.nix --arg cross true --arg internet true

flake.nix:
  nix develop ./tester_setup/nix#cross-rpi4-internet   # cross + internet
  nix develop ./tester_setup/nix#internet               # only internet (native build)
  nix develop ./tester_setup/nix#cross-rpi4             # only cross deploy
  nix develop ./tester_setup/nix                        # default
