#!/usr/bin/env bash

set -eu


log(){  
  echo  "$(date '+%H:%M:%S') $1"
}

ensure_venv() {
  if [ ! -d venv ]; then
    virtualenv -p $(which python3.6) venv
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

get_local_target(){
  # TOOD: select local system
  echo "linux"
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

  target=${1:-"defaultvalue"}
  if [ "$target" == "defaultvalue" ]; then
    target=$(get_local_target)
  else
    shift;
  fi
  
  type=${1:-"defaultvalue"}
  if [ "$type" == "defaultvalue" ]; then
    type="release=1"
  else
    shift;
    if [ "$type" == "release" ]; then
      type="release=1"
    else
      type="debug=1"
    fi    
  fi
  
  
  scons "$type" "target=$target" "$@"
}

task_build_local() {
  task_build $(get_local_target) "$@"
}

task_clean() {
  ensure_venv

  rm -rf build
  scons -c
}

task_doc() {
  ensure_venv
  (
    rm -rf build/doc
    mkdir -p build/doc
    make html -C doc BUILDDIR='../build/doc'        
  )
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
  folder="neuropil/deployment"
  enviroment="$1"

  case "$enviroment" in
    test) 
      folder="$folder/testing";;
    production)
      folder="$folder/base";;
    *) 
      log "No such enviroment '$enviroment' known. (known: test|production)"; exit 1;;
  esac

  rsync -e ssh -hrv --exclude=".git/" --exclude="venv/" ./build/package/* "gitlab-runner@neuro0.in.pi-lar.net:$folder"

  log "Deployment ready for salt interaction"
}

task_install_python() {
  ensure_venv
  
  task_build_local release python_binding=1
}

task_test() {
  ensure_venv
  ensure_submodules
  ensure_criterion  

  task_build "test" debug test=1
  export LD_LIBRARY_PATH=./build/test/ext_tools/Criterion/build:./build/test/lib
  ./build/test/bin/neuropil_test_suite -j1 --xml=neuropil_test_suite-junit.xml "$@"
}

task_smoke() {
  ensure_venv
  task_install_python

  pwd=$(pwd)
  (
    loc="$(get_local_target)"    

    echo "export LD_LIBRARY_PATH=$pwd/build/$loc/lib"
    export LD_LIBRARY_PATH="$pwd/build/$loc/lib"
    set +e         
    nose2 -v
    if [ $? == 139 ] && [ -t 0 ]; then      
      read -r -p "${1:-Debug with gdb? [y/N]} " response
      case "$response" in
          [yY][eE][sS]|[yY])
              gdb --silent -ex=r --args nose2 -v
              ;;
          *)
              ;;
      esac
    fi
    set -e

  )
}

task_test_deployment() {
  task_test
  task_build linux
  #task_build freebsd
  task_doc
  task_package
  task_install_python
  task_smoke
  #task_deploy test
}
usage() {
  echo "$0  build | lbuild | test | clean | package | release | deploy | smoke | doc | prepare_ci | deploy"
  exit 1
}

cmd="${1:-}"
shift || true

(
  cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

  case "$cmd" in
    clean) task_clean ;;
    lbuild) task_build_local "$@";;
    build) task_build "$@";;
    doc) task_doc ;;
    test) task_test "$@";;
    package) task_package "$@";;  
    install_python) task_install_python ;;
    smoke) task_smoke ;;
    release) task_release ;;

    prepare_ci) task_prepare_ci ;;
    deploy) task_deploy "$1";;

    test_deployment) task_test_deployment ;;
    *) usage ;;
  esac
)
