{
  source ? ../../ext_tools/qcbor,
  stdenv,
  lib,
}:
stdenv.mkDerivation {
  pname = "qcbor";
  version = "bundled";
  src = source;

  nativeBuildInputs = [];

  CMD_LINE = lib.concatStringsSep " " [
    "-DQCBOR_DISABLE_ENCODE_USAGE_GUARDS"
    "-DQCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS"
    "-DQCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS"
    "-DQCBOR_DISABLE_PREFERRED_FLOAT"
  ];

  installPhase = ''
    mkdir "$out"

    PREFIX="$out" make install
    PREFIX="$out" make install_so
  '';
}
