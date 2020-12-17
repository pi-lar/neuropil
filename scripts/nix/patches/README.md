
# Patches
Use header files directly from the nix output of neuropil instead of files in the project directory

If you change the build scripts in such a way that they become incompatible with these patch files please make sure to also reproduce this patch for nix compatibility.

## `bindings/python_cffi/neuropil_build.py`

From the project directory after making the nix related changes run

``` bash
$ git diff --relative=bindings/python_cffi \
  bindings/python_cffi/neuropil_build.py > \
  scripts/nix/patches/neuropil_build.py.patch
```

to generate the corresponding patch.
You can now revert this change to "non-nix" behaviour.

## `neuropil/bindings/luajit/build.sh`

From the project directory after making the nix related changes run

``` bash
$ git diff --relative=neuropil/bindings/luajit/ \
  neuropil/bindings/luajit/build.sh > \
  scripts/nix/patches/build.sh.patch
```

to generate the corresponding patch.
You can now revert this change to "non-nix" behaviour.
