# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result

{ pkgs ? (import <nixpkgs> {}), source ? ../../., version ? "dev" }:

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
        lib.any (prefix: lib.hasPrefix prefix relPath) [ "include" "framework" "src" "SConstruct" "examples" ]
  )
    source;

  buildInputs = [ git scons ncurses python3Packages.requests sqlite libsodium ];
  nativeBuildInputs = []
  ++ stdenv.lib.optional stdenv.isDarwin fixDarwinDylibNames;

  inherit version;

  buildPhase = ''
    if [ ${version} = dev ]; then
        scons debug=1 program=lib_only
    elif [ ${version} = prod ]; then
        scons release=1 program=lib_only
    fi
  '';

  installPhase = ''
    mkdir -p $out/{lib,include}
    cp -r build/neuropil/lib/* $out/lib
    cp -r include/neuropil* $out/include
  '';

  dontStrip = true;
}
