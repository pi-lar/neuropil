#!/usr/bin/env bash

set -eu


ensure_venv() {
  if [ ! -d venv ]; then
    virtualenv -p $(which python3) venv
    ./venv/bin/pip3 install -r requirements.txt
  fi

  if [ requirements.txt -nt venv ]; then
    ./venv/bin/pip3 install -r requirements.txt
    touch ./venv
  fi
  set +u
  source ./venv/bin/activate
  set -u
}

ensure_submodules() {
  git submodule update --init --recursive
}

ensure_criterion() {
  if  [ -e ./build/test/ext_tools/Criterion/build/libcriterion.so ];
  then
    return
  fi
  ( 
  root="$(pwd)"
  mkdir -p build/test/ext_tools/Criterion/build
  cd build/test/ext_tools/Criterion/build
  cmake "${root}/ext_tools/Criterion"
  cmake --build .
  )
}

task_build() {
  ensure_venv
  ensure_submodules

  scons release=1 target="$1"
}

task_debug() {
  ensure_venv
  ensure_submodules

  scons debug=1 "$@"
}

task_clean() {
  ensure_venv

  scons -c
}

task_doc() {
  ensure_venv

  scons doc=1 target=doc
}

task_test() {
  ensure_venv
  ensure_submodules
  ensure_criterion  

  scons debug=1 test=1 target=test
  export LD_LIBRARY_PATH=./build/test/ext_tools/Criterion/build:./build/test/lib
  ./build/test/bin/neuropil_test_suite -j1 --xml=report.xml "$@"
}

usage() {
  echo "$0  build | debug | test | clean"
  exit 1
}

cmd="${1:-}"
shift || true
case "$cmd" in
  build) task_build "$1";;
  test) task_test "$@";;
  debug) task_debug "$@";;
  doc) task_doc ;;
  clean) task_clean ;;
  *) usage ;;
esac
