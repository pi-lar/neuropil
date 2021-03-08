{ pkgs ? (import <nixpkgs> {})
, version ? "dev"
, withLuajit ? true
, withPython ? true
}:

with pkgs;

let
  neuropil_luajit =
    callPackage ./neuropil-luajit.nix { neuropil = libneuropil; inherit pkgs; };
  neuropil_python =
    callPackage ./neuropil-python.nix { neuropil = libneuropil; inherit pkgs; };
in
mkShell rec {
  name = "neuropil-shell";

  buildInputs = [ clang libneuropil ]
  ++ lib.optionals withLuajit [ neuropil_luajit luajit ]
  ++ lib.optionals withPython
    [
      (
        python3.withPackages (
          ps: with ps; [
            neuropil_python
          ]
        )
      )
    ];

  shellHook = ''
    export LD_LIBRARY_PATH="${lib.makeLibraryPath [ libneuropil ]}"
  '' + lib.optionalString withLuajit ''
    export LUA_PATH="${luajitPackages.getLuaPath neuropil_luajit}"
  '';
}
