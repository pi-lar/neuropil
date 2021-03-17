# SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

(import (fetchTarball
  "https://github.com/edolstra/flake-compat/archive/master.tar.gz") {
    src = builtins.fetchGit ./.;
  }).shellNix
