# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result
{
  source ? ../../bindings/luajit,
  neuropil,
  lib,
  luajitPackages,
  clang,
  luajit,
}: let
  version = neuropil.version;
in
  luajitPackages.buildLuaPackage rec {
    pname = "neuropil-luajit";
    src = lib.cleanSource source;

    # Gnerate using:
    # $ git diff --relative=bindings/luajit \
    # bindings/luajit/build.sh >          \
    # scripts/nix/patches/build.sh.patch
    #
    patches = [./patches/build.sh.patch];
    buildInputs = [clang neuropil luajit];
    inherit version;
    inherit neuropil;

    buildPhase = "sh ./build.sh";

    installPhase = ''
      install -Dt "$out/share/lua/${luajit.luaversion}" \
              neuropil.lua
      install -Dt "$out/share/lua/${luajit.luaversion}" \
              build/neuropil_ffi.lua
    '';
  }
