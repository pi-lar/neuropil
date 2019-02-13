# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result

{ pkgs ? (import <nixpkgs> {}), source ? ./., version ? "dev" }:

with pkgs;

let
  neuropil = import ../../default.nix {};
  neuropil_luajit = import ../../neuropil-luajit.nix {};
in stdenv.mkDerivation rec {
  name = "neuropil-test-integration-${version}";
  src = lib.cleanSource source;

  buildInputs = [ neuropil neuropil_luajit luajit ];
  inherit version;

  buildPhase = ''
    export LD_LIBRARY_PATH="${lib.makeLibraryPath [ neuropil ]}"
    export LUA_PATH="${luajitPackages.getLuaPath neuropil_luajit}"
    for test in *.lua; do
        echo -n "Running test $test..."
        ((luajit $test 2>&1 && echo OK) || true) \
                | tee "$(basename "$test" .lua).log"
    done
  '';

  installPhase = ''
    mkdir -p $out
    cp *.log $out/
  '';
}
