# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
{
  source ? ../../bindings/python_cffi,
  python3Packages,
  lib,
  clang,
  libsodium,
  neuropil,
}:
python3Packages.buildPythonPackage rec {
  pname = "neuropil-python";
  version = neuropil.version;
  src = lib.cleanSource source;
  # patches = [ ./patches/neuropil_build.py.patch ];
  buildInputs = [clang libsodium neuropil];
  propagatedBuildInputs = [python3Packages.cffi];
  inherit neuropil;
}
