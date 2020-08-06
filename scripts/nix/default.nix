# Run like this:
#   nix-build /path/to/this/directory
# ... build products will be in ./result

{ pkgs ? (import <nixpkgs> {}), source ? ./., version ? "dev" }:

with pkgs;

let
  stdenv = clangStdenv;
in stdenv.mkDerivation rec {
  name = "neuropil-${version}";
  src = lib.cleanSource source;

  buildInputs = [ scons libsodium ncurses sqlite ];
  inherit version libsodium ncurses sqlite;

  postPatch = ''
    sed -i -e "s@default_env = Environment(CC = 'clang')@default_env = Environment(ENV = os.environ)@" SConstruct
  '';

  buildPhase = ''
    if [ ${version} = dev ]; then
        scons debug=1
    else
        scons release=1
    fi
  '';

  installPhase = ''
    mkdir -p $out/lib
    cp build/lib/libneuropil.so $out/lib
  '';

  dontStrip = true;
}
