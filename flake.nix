{
  description =
    "neuropil is a secure messaging library for IoT, robotics and more.";

  inputs.nixpkgs = {
    type = "github";
    owner = "NixOS";
    repo = "nixpkgs";
    ref = "nixos-20.09";
  };

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
          neuropil_luajit = callPackage ./scripts/nix/neuropil_luajit.nix {
            neuropil = libneuropil;
            pkgs = final;
          };
          neuropil_python = callPackage ./scripts/nix/neuropil_python.nix {
            neuropil = libneuropil;
            pkgs = final;
          };
          neuropil_shell = callPackage ./scripts/nix/shell { pkgs = final; };
        };

      packages = forAllSystems (system: {
        libneuropil = nixpkgsFor.${system}.libneuropil;
        shell = nixpkgsFor.${system}.neuropil_shell;
        integration.luajit = nixpkgsFor.${system}.neuropil_luajit;
        integration.python = nixpkgsFor.${system}.neuropil_python;
      });

      defaultPackage =
        forAllSystems (system: self.packages.${system}.libneuropil);
    };
}
