# SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
(import (fetchTarball
  "https://github.com/edolstra/flake-compat/archive/master.tar.gz") {
  src = builtins.fetchGit ./.;
})
.shellNix
