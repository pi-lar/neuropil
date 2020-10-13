{ pkgs ? (import <nixpkgs> { }), version ? "dev", withLuajit ? true
, withPython ? true }:

with pkgs;

let
  neuropil = callPackage ./neuropil.nix { inherit version pkgs; };
  neuropil_luajit =
    callPackage ./neuropil-luajit.nix { inherit neuropil pkgs; };
  neuropil_python =
    callPackage ./neuropil-python.nix { inherit neuropil pkgs; };
in mkShell rec {
  name = "neuropil-shell";

  buildInputs = [ clang neuropil ]
    ++ lib.optionals withLuajit [ neuropil_luajit luajit ]
    ++ lib.optionals withPython
    [ (python3.withPackages (ps: [ neuropil_python ])) ];

  shellHook = ''
    export LD_LIBRARY_PATH="${lib.makeLibraryPath [ neuropil ]}"
  '' + lib.optionalString withLuajit ''
    export LUA_PATH="${luajitPackages.getLuaPath neuropil_luajit}"
  '';
}
