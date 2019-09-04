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

task_prepare_ci(){
  eval $(ssh-agent -s)

  ##
  ## Add the SSH key stored in SSH_PRIVATE_KEY variable to the agent store
  ## We're using tr to fix line endings which makes ed25519 keys work
  ## without extra base64 encoding.
  ## https://gitlab.com/gitlab-examples/ssh-private-key/issues/1#note_48526556
  ##
  echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add - > /dev/null
}

task_build() {
  ensure_venv
  ensure_submodules

  scons release=1 target="$1"
}

task_build_debug() {
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

task_package() {
  ensure_venv

  ./build_info.py --package "$@"
}

task_release() {
    ensure_venv

  ./build_info.py --gitlab_release
}

task_deploy() {

  ssh -o StrictHostKeyChecking=no demo_deploy /usr/local/bin/supervisorctl stop all
  ssh -o StrictHostKeyChecking=no demo_deploy rm neuropil/*neuropil*
  scp -r bin/. demo_deploy:/home/neuropil_deploy/neuropil
  scp -r build/lib/. demo_deploy:/home/neuropil_deploy/neuropil
  ssh -o StrictHostKeyChecking=no demo_deploy /usr/local/bin/supervisorctl start all
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
  echo "$0  build | build_debug | test | clean | package | release | deploy"
  exit 1
}

cmd="${1:-}"
shift || true
case "$cmd" in
  build) task_build "$1";;
  test) task_test "$@";;
  build_debug) task_build_debug "$@";;
  package) task_package "$@";;
  release) task_release ;;
  deploy) task_deploy ;;
  doc) task_doc ;;
  prepare_ci) task_prepare_ci ;;
  clean) task_clean ;;
  *) usage ;;
esac
