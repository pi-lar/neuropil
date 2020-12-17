{
  description =
    "neuropil is a secure messaging library for IoT, robotics and more.";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?release-20.09";

  outputs = { self, nixpkgs, ... }:

    let
      # Generate a user-friendly version numer.
      version = builtins.substring 0 8 (./.).lastModifiedDate;

      # System types to support.
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = f:
        nixpkgs.lib.genAttrs supportedSystems (system: f system);

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system:
        import nixpkgs {
          inherit system;
          overlays = [ self.overlay ];
        });

    in {
      overlay = final: prev:
        with final; rec {
          libneuropil = callPackage ./scripts/nix/neuropil.nix {
            pkgs = final;
            version = "prod";
          };
          neuropil_luajit = callPackage ./scripts/nix/neuropil-luajit.nix {
            neuropil = libneuropil;
            pkgs = final;
          };
          neuropil_python = callPackage ./scripts/nix/neuropil-python.nix {
            neuropil = libneuropil;
            pkgs = final;
          };
          neuropil_shell =
            callPackage ./scripts/nix/shell.nix { pkgs = final; };
        };

      packages = forAllSystems (system: {
        libneuropil = nixpkgsFor.${system}.libneuropil;
        shell = nixpkgsFor.${system}.neuropil_shell;
        neuropil_luajit = nixpkgsFor.${system}.neuropil_luajit;
        neuropil_python = nixpkgsFor.${system}.neuropil_python;
      });

      defaultPackage =
        forAllSystems (system: self.packages.${system}.libneuropil);

      devShell = forAllSystems (system: self.packages.${system}.shell);

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) libneuropil;

        # Additional tests, if applicable.
        test-import-lib = with nixpkgsFor.${system};
          pkgs.runCommandCC "test-import-lib" {
            buildInputs = [ libneuropil ];
          } ''
            echo 'try building with library'
            $CC -lneuropil ${./examples/neuropil_receiver.c}
            touch $out
          '';

        test-import-python = with nixpkgsFor.${system};
          pkgs.runCommand "test-import-python" {
            buildInputs = [ neuropil_python ];
          } ''
            echo 'try importing python module'
            python -c 'import neuropil'
            touch $out
          '';

        test-import-lua = with nixpkgsFor.${system};
          pkgs.runCommand "test-import-lua" {
            buildInputs = [ neuropil_lua ];
          } ''
            echo 'try importing lua module'
            luajit  <(echo 'require "neuropil"')
            touch $out
          '';

        test-scons = with nixpkgsFor.${system};
          stdenv.mkDerivation {
            name = "test-scons";
            src = libneuropil.src;
            buildInputs = [ scons libsodium sqlite ncurses ];
            buildPhase = ''
              scons test=1
            '';
            installPhase = "touch $out";
          };
      });

    };
}
