# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result

{ pkgs ? (import <nixpkgs> {}), source ? ./., version ? "dev" }:

with pkgs;

let
  stdenv = clangStdenv;
  neuropil = import ./default.nix {};
in luajitPackages.buildLuaPackage rec {
  name = "neuropil-luajit-${version}";
  src = lib.cleanSource source;

  buildInputs = [ clang ];
  inherit version luajit neuropil;

  buildPhase = ''
    make bindings/luajit/neuropil_ffi.lua
  '';

  installPhase = ''
    install -Dt "$out/lib/lua/${luajit.luaversion}" \
            bindings/luajit/neuropil*.lua
  '';

  shellHook = ''
     export LD_LIBRARY_PATH="${lib.makeLibraryPath [ neuropil ]}"
     export LUA_PATH="$PWD/bindings/luajit/?.lua"
  '';
}
