# SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result

{ pkgs ? (import <nixpkgs> {}), source ? ../../., version ? "dev", ext }:

with pkgs;

let
  stdenv = clangStdenv;
in
stdenv.mkDerivation rec {
  name = "neuropil-${version}";
  src = builtins.filterSource (
    path: type:
      let
        relPath = (lib.removePrefix (toString source + "/") path);
      in
        lib.any (prefix: lib.hasPrefix prefix relPath) [ "include" "framework" "src" "SConstruct" "examples" "ext_tools" "scripts" "test" ]
  )
  source;

  buildInputs = [ git  ncurses scons (python3.withPackages (p: [p.requests])) sqlite libsodium ];
  nativeBuildInputs = []
  ++ stdenv.lib.optional stdenv.isDarwin fixDarwinDylibNames;

  inherit version;

  buildPhase = ''
    rm -rf ext_tools/msgpack
    rm -rf ext_tools/parson
    ln -s ${ext.msgpack-cmp} ext_tools/msgpack
    ln -s ${ext.parson} ext_tools/parson
    ls -la ext_tools/msgpack
    if [ ${version} = dev ]; then
        scons --DEBUG shared_neuropil
    elif [ ${version} = prod ]; then
        scons --RELEASE shared_neuropil
    fi
  '';

  installPhase = ''
    mkdir -p $out/{lib,include}
    cp -r build/neuropil/lib/* $out/lib
    cp -r include/neuropil* $out/include
  '';

  dontStrip = true;
}
