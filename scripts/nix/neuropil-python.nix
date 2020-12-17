{ pkgs ? (import <nixpkgs> {})
, source ? ../../bindings/python_cffi
, neuropil ? pkgs.callPackage ./neuropil.nix {}
}:

with pkgs;
python37Packages.buildPythonPackage rec {
  name = "neuropil-python";
  src = lib.cleanSource source;
  patches = [ ./patches/neuropil_build.py.patch ];
  buildInputs = [ clang libsodium neuropil ];
  propagatedBuildInputs = [ python37Packages.cffi ];
  inherit neuropil;
}
