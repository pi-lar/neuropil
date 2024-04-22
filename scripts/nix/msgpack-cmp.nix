{
  source ? ../../ext_tools/msgpack,
  stdenv,
  gccStdenv,
}:
stdenv.mkDerivation {
  pname = "msgpack";
  version = "bundled";
  src = source;

  buildPhase = ''
    $CC $CFLAGS $CMPCFLAGS -g -I. -c cmp.c
  '';

  CMPCFLAGS = "-std=c99 -fPIC -o libcmp.so";

  installPhase = ''
    mkdir -p $out/{lib,obj,include}/cmp
    cp ./libcmp.so "$out/lib/libcmp.so"
    cp ./cmp.h "$out/include/cmp/cmp.h"
  '';
}
