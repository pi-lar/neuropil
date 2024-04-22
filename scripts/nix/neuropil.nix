# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result
{
  source ? ../../.,
  version ? "dev",
  msgpack-cmp,
  parson,
  qcbor,
  criterion,
  git,
  ncurses,
  scons,
  python3,
  sqlite,
  libsodium,
  fixDarwinDylibNames,
  stdenv,
  lib,
}:
stdenv.mkDerivation rec {
  name = "neuropil-${version}";
  src =
    builtins.filterSource (
      path: type: let
        relPath = lib.removePrefix (toString source + "/") path;
      in
        lib.any (prefix: lib.hasPrefix prefix relPath) ["include" "framework" "src" "SConstruct" "examples" "ext_tools" "scripts" "test"]
    )
    source;

  buildInputs = [ncurses sqlite libsodium parson criterion qcbor msgpack-cmp];
  nativeBuildInputs =
    [
      git
      scons
      (python3.withPackages (p: [p.requests]))
    ]
    ++ lib.optional stdenv.isDarwin fixDarwinDylibNames;

  inherit version;

  buildPhase = ''
    mkdir build

    if [ ${version} = dev ]; then
        scons -C build -f ../SConstruct --DEBUG
    elif [ ${version} = prod ]; then
        scons -C build -f ../SConstruct
    fi
  '';

  installPhase = ''
    mkdir -p $out/{include,lib,bin}
    cp -r include/neuropil* $out/include
    cp -r build/neuropil/lib/* $out/lib
    cp -r build/neuropil/bin/* $out/bin
  '';

  dontStrip = true;
}
