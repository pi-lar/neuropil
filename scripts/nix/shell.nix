{ pkgs ? (import <nixpkgs> {})}:

with pkgs;

let
  neuropil = import ./default.nix {};
  neuropil_luajit = import ./neuropil-luajit.nix {};
in stdenv.mkDerivation rec {
  name = "neuropil-shell";

  buildInputs = [ clang scons neuropil neuropil_luajit luajit ];

  shellHook = ''
    export LD_LIBRARY_PATH="${lib.makeLibraryPath [ neuropil ]}"
    export LUA_PATH="${luajitPackages.getLuaPath neuropil_luajit}"
  '';
}
