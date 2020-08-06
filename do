#!/usr/bin/env bash

set -eu

ensure_venv() {
  if [ ! -d .venv ]; then
    virtualenv -p $(which python3) .venv
    ./.venv/bin/pip3 install -r configs/requirements.txt
  fi

  if [ configs/requirements.txt -nt .venv ]; then
    ./.venv/bin/pip3 install -r configs/requirements.txt
    touch ./.venv
  fi
  set +u
  source ./.venv/bin/activate
  set -u
}

ensure_submodules() {
  git submodule update --init --recursive
}

ensure_criterion() {
  echo "check for existing criterion installation"
  set +e
  ldconfig -p | grep criterion
  e=$?
  set -e
  if [ e == 0 ];
  then
    echo "found criterion"
    return
  fi
  (
    echo "did not find criterion. Building now"
    root="$(pwd)"
    mkdir -p "build/ext_tools/Criterion/build"
    cd ext_tools/Criterion
    meson "${root}/build/ext_tools/Criterion/build"
    ninja -C "${root}/build/ext_tools/Criterion/build"
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

  tmpfile_sorted=$(mktemp /tmp/np_sorted.log.XXXXXX)
  tmpfile_sorted2=$(mktemp /tmp/np_sorted.log.XXXXXX)

  echo "executing: scons -C build -f ../SConstruct $type $@ |& tee $tmpfile_sorted"
  (scons -C build -f ../SConstruct "$type" "$@" |& tee "$tmpfile_sorted")
  ret=${PIPESTATUS[0]}
  set +e
  egrep "warning:|error:" "$tmpfile_sorted" > "$tmpfile_sorted2"
  filterd=$(cat "$tmpfile_sorted2")
  if [ "$?" == "0" ]; then
    filterd=$(echo "$filterd" | sort)
    filterd=$(echo "$filterd" | grep -v "/event/")
    filterd=$(echo "$filterd" | uniq)
    echo "$filterd"

    warnings=$(echo "$filterd" | grep "warning:")
    if [ "$?" != "0" ]; then
      warn="0"
    else
      warn=$(echo "$warnings" | wc -l)
    fi
    errors=$(echo "$filterd" | grep "error:")
    if [ "$?" != "0" ]; then
      err="0"
    else
      err=$(echo "$errors" | wc -l)
    fi
    echo "$warnings"
    echo "$errors"
    printf "Warnings:\t%s\n" "$warn"
    printf "Errors:\t\t%s\n" "$err"
  fi
  set -e

  return $ret
}

task_clean() {
  ensure_venv

  git submodule foreach --recursive git clean -xfd
  git submodule foreach --recursive git reset --hard
  git submodule update --init --recursive
  rm -rf logs/*
  rm -rf bindings/python_cffi/build bindings/python_cffi/_neuropil.abi3.so bindings/python_cffi/neuropil.egg-info
  rm -rf build
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

  ./scripts/util/build_helper.py --package "$@"
}

task_release() {
    ensure_venv

  ./scripts/util/build_helper.py --gitlab_release
}

task_install_python() {
  ensure_venv
  task_build release "$@"
  task_build release python_binding=1 "$@"
  pip3 install -e bindings/python_cffi

  if [ "$(uname -s)" == "Mac" ]
  then
      echo "Trying to use name tool to link into build library in ${work_dir}/_neuropil.abi3.so"
      sudo install_name_tool -change build/neuropil/lib/libneuropil.dylib ${base_dir}/build/neuropil/lib/libneuropil.dylib ./_neuropil.abi3.so
      last=$?
  fi

  return $?
}

task_test() {
  ensure_venv
  ensure_submodules
  ensure_criterion

  task_build debug

  (
    cd build
    mkdir -p logs
    if [[ $? == 0 ]] ; then
      export LD_LIBRARY_PATH=./ext_tools/Criterion/build/src:./neuropil/lib:"$LD_LIBRARY_PATH"

      ./neuropil/bin/neuropil_test_suite -j1 --xml=neuropil_test_suite-junit.xml "$@"
      # Enable for test debugging
      #nohup ./build/neuropil/bin/neuropil_test_suite --debug=gdb -j1 --xml=neuropil_test_suite-junit.xml "$@" &>/dev/null &
      #sleep 1
      #gdb ./build/neuropil/bin/neuropil_test_suite -ex "target remote localhost:1234" -ex "continue"
    fi
  )
}

task_run() {
  application=${1:-"defaultvalue"}
  if [ "$application" == "defaultvalue" ]; then
    application="neuropil_node"
  else
    application="neuropil_$application"
    shift;
  fi
  application="$application"

  export LD_LIBRARY_PATH="./build/neuropil/lib:$LD_LIBRARY_PATH"

  echo "./build/neuropil/bin/$application" "$@"
  set +e
  run=$("./build/neuropil/bin/$application" "$@")
  set -e
  if [ "$run" != 0 ] ; then
    gdb "./build/neuropil/bin/$application" -c core*
  fi

}

task_smoke() {
  pwd=$(pwd)
  (
    ensure_venv
    task_install_python

    cd build
    mkdir -p logs
    echo "export LD_LIBRARY_PATH=$pwd/build/neuropil/lib:$LD_LIBRARY_PATH"
    export LD_LIBRARY_PATH="$pwd/build/neuropil/lib:$LD_LIBRARY_PATH"

    set +e
    nose2 -v --config ../configs/nose2.cfg
    e=$?
    if [ e == 139 ] && [ -t 0 ]; then
      read -r -p "${1:-Debug with gdb? [y/N]} " response
      case "$response" in
          [yY][eE][sS]|[yY])
              gdb --silent -ex=r --args nose2 -v --config config/snose2.cfg
              ;;
          *)
              ;;
      esac
    fi
    set -e
    return $e
  )
}

task_ensure_dependencies() {
  ensure_venv
  ensure_submodules
  ensure_criterion
  (
    cd "build/ext_tools/Criterion/build"
    #ninja install
  )
  echo "installing git hooks"
  ln -s ../../.git_hooks/pre-commit .git/hooks/pre-commit
  echo "neuropil development enviroment is ready"
}

task_test_deployment() {
  task_test
  task_build release
  #task_build freebsd
  task_doc
  task_package
  task_install_python
  task_smoke
}
task_pre_commit(){
  ensure_venv

  python3 scripts/util/build_helper.py --update_strings
}
usage() {
  echo "$0  build | test | clean | package | release | deploy | smoke | doc | prepare_ci | (r)un | ensure_dependencies | pre_commit"
  exit 1
}

cmd="${1:-}"
shift || true

(
  cd "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
  mkdir -p build

  if [ -z "${LD_LIBRARY_PATH:-}" ]
  then
    export LD_LIBRARY_PATH=""
  fi

  case "$cmd" in
    clean) task_clean ;;
    build) task_build "$@";;
    doc) task_doc ;;
    test) task_test "$@";;
    package) task_package "$@";;
    install_python) task_install_python ;;
    smoke) task_smoke ;;
    release) task_release ;;
    run) task_run "$@";;
    r) task_run "$@";;
    ensure_dependencies) task_ensure_dependencies;;

    prepare_ci) task_prepare_ci ;;
    pre_commit) task_pre_commit ;;

    test_deployment) task_test_deployment ;;
    *) usage ;;
  esac
)
