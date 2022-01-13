# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

{ pkgs ? (import <nixpkgs> {})
, source ? ../../bindings/python_cffi
, neuropil ? pkgs.callPackage ./neuropil.nix {}
}:

with pkgs;
python3Packages.buildPythonPackage rec {
  name = "neuropil-python";
  src = lib.cleanSource source;
  # patches = [ ./patches/neuropil_build.py.patch ];
  buildInputs = [ clang libsodium neuropil ];
  propagatedBuildInputs = [ python3Packages.cffi ];
  inherit neuropil;
}
