# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
{
  description = "neuropil is a secure messaging library for IoT, robotics and more.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?release-20.09";

    msgpack-cmp-src = {
      url = "github:camgunz/cmp/9fc01ddf4fd41d87267267a3221c92225c383e07";
      flake = false;
    };

    qcbor-src = {
      url = "github:laurencelundblade/QCBOR/07653df2bbdb2d090d98d0df514fa019ac23dff3";
      flake = false;
    };
  };
  outputs = {
    self,
    nixpkgs,
    msgpack-cmp-src,
    qcbor-src,
    ...
  }: let
    # Generate a user-friendly version numer.
    version = builtins.substring 0 8 ./..lastModifiedDate;

    # System types to support.
    supportedSystems = ["x86_64-linux" "x86_64-darwin" "aarch64-darwin"];

    # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
    forAllSystems = f:
      nixpkgs.lib.genAttrs supportedSystems (system: f system);

    # Nixpkgs instantiated for supported system types.
    nixpkgsFor = forAllSystems (system:
      import nixpkgs {
        inherit system;
        overlays = [self.overlay];
      });
  in {
    overlay = final: prev:
      with final; {
        neuropil = callPackage ./scripts/nix/neuropil.nix {
          version = "prod";
        };
        neuropil_luajit =
          callPackage ./scripts/nix/neuropil-luajit.nix {
          };
        neuropil_python =
          callPackage ./scripts/nix/neuropil-python.nix {
          };

        neuropil_shell =
          callPackage ./scripts/nix/shell.nix {pkgs = final;};

        qcbor =
          callPackage ./scripts/nix/qcbor.nix {source = qcbor-src;};

        msgpack-cmp =
          callPackage ./scripts/nix/msgpack-cmp.nix {source = msgpack-cmp-src;};
      };

    packages = forAllSystems (system: {
      default = self.packages.${system}.neuropil;

      inherit (nixpkgsFor.${system}) neuropil neuropil_luajit neuropil_python qcbor msgpack-cmp;
    });

    devShells = forAllSystems (system: {
      default = self.devShells.${system}.neuropil_shell;
      inherit (nixpkgsFor.${system}) neuropil_shell;
    });

    checks = forAllSystems (system: {
      inherit (self.packages.${system}) neuropil;

      # Additional tests, if applicable.
      test-import-lib = with nixpkgsFor.${system};
        pkgs.runCommandCC "test-import-lib" {
          buildInputs = [neuropil];
        } ''
          echo 'try building with library'
          $CC -lneuropil ${./examples/neuropil_receiver.c}
          touch $out
        '';

      test-import-python = with nixpkgsFor.${system};
        pkgs.runCommand "test-import-python" {
          buildInputs = [neuropil_python];
        } ''
          echo 'try importing python module'
          python -c 'import neuropil'
          touch $out
        '';

      test-import-lua = with nixpkgsFor.${system};
        pkgs.runCommand "test-import-lua" {
          buildInputs = [neuropil_luajit neuropil];
        } ''
          export LD_LIBRARY_PATH="${lib.makeLibraryPath [neuropil]}"
          echo 'try importing lua module'
          luajit  <(echo 'require("neuropil")')
          touch $out
        '';

      # test-scons = with nixpkgsFor.${system};
      #   stdenv.mkDerivation {
      #     name = "test-scons";
      #     src = neuropil.src;
      #     buildInputs = [ scons libsodium sqlite ncurses criterion (python3.withPackages (p: [p.requests])) ];
      #     buildPhase = ''
      #     ln -s ${msgpack-cmp} ext_tools/msgpack
      #     ln -s ${parson} ext_tools/parson
      #       scons --RELEASE tests
      #     '';
      #     installPhase = "touch $out";
      #   };
    });
  };
}
