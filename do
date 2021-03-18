#!/usr/bin/env bash

# colorcodes https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

set -eu

ensure_venv() {
  if [ ! -d .venv ]; then
    python3 -m venv .venv
    ./.venv/bin/pip3 install --upgrade pip
    ./.venv/bin/pip3 install --upgrade setuptools wheel
    ./.venv/bin/pip3 install -r configs/requirements.txt
  fi

  if [ configs/requirements.txt -nt .venv ]; then
    ./.venv/bin/pip3 install --upgrade pip
    ./.venv/bin/pip3 install --upgrade setuptools wheel
    ./.venv/bin/pip3 install -r configs/requirements.txt
    touch ./.venv
  fi
  set +u
  source ./.venv/bin/activate
  set -u
}

task_build() {
  ensure_venv
  ret=100
  tmpfile_sorted=$(mktemp /tmp/np_sorted.log.XXXXXX)
  echo "executing: scons -C build -f ../SConstruct $@"
  set +e
  scons -C build -f ../SConstruct "$@" 2>&1 | tee "$tmpfile_sorted"
  ret=${PIPESTATUS[0]}

  unsorted=$(cat "$tmpfile_sorted")
  rm "$tmpfile_sorted"

  warnings=$( echo "$unsorted" | grep 'warning:'                                                                     |sort|grep -v "/event/"|uniq)
    errors=$( echo "$unsorted" | grep 'error:\|scons: building terminated because of errors\|undefined reference to' |sort|grep -v "/event/"|uniq)

  warn_no=$( echo "$warnings" | wc -l)
  err_no=$( echo "$errors" | wc -l)

  if [ "$warnings" != "" ]; then
    echo -e "${ORANGE}Custom warning listing (${warn_no}):${NC}"
    echo "$warnings"
  else
    warn_no=0
  fi
  if [ "$errors" != "" ]; then
    echo -e "${RED}Custom error listing (${err_no}):${NC}"
    echo "$errors"
  else
    err_no=0
  fi
  printf "Warnings:\t%s\n" "$warn_no"
  printf "Errors:\t\t%s\n" "$err_no"
  set -e
  return $ret
}

task_analyze() {
  ensure_venv
  ret=-1

  (
    cd build

    rm -rf neuropil/*
    set +e
    scan-build -o analyze -stats --status-bugs scons -C build -f ../SConstruct "$@"
    ret=$?
    set -e
  )

  return $ret
}

task_clean() {
  ensure_venv

  git submodule foreach --recursive git clean -xfd
  git submodule foreach --recursive git reset --hard
  rm -rf logs/*
  rm -rf bindings/python_cffi/build bindings/python_cffi/_neuropil.abi3.so bindings/python_cffi/neuropil.egg-info bindings/python_cffi/dist/*
  rm -rf build
  scons -f ./SConstruct -c
}

task_doc() {
  ensure_venv
  (
    rm -rf build/doc
    mkdir -p build/doc

    make='make'
    unamestr=$(uname)
    if [ "$unamestr" = 'FreeBSD' ]; then
      make='gmake'
    fi
    $make html -C doc BUILDDIR='../build/doc'
  )
}

task_package() {
  ensure_venv

  ./scripts/util/build_helper.py --package "$@"
}

task_install_python() {
  ensure_venv
  pip3 install -e bindings/python_cffi

  if [ "$(uname -s)" == "Mac" ]
  then
      echo "Trying to use name tool to link into build library in ${work_dir}/_neuropil.abi3.so"
      sudo install_name_tool -change build/neuropil/lib/libneuropil.dylib ${base_dir}/build/neuropil/lib/libneuropil.dylib ./_neuropil.abi3.so
      last=$?
  fi

  return $?
}

task_coverage() {
  ensure_venv

  task_build --DEBUG --CODE_COVERAGE tests

  (
    cd build
    mkdir -p logs
    if [[ $? == 0 ]] ; then
      echo "$(pwd)/neuropil_test_suite.profraw"
      LLVM_PROFILE_FILE="$(pwd)/neuropil_test_suite.profraw" ./neuropil/bin/neuropil_test_suite -j1 --xml=neuropil_test_suite-junit.xml "$@"

      llvm-profdata merge -sparse "$(pwd)/neuropil_test_suite.profraw" -o "$(pwd)/neuropil_test_suite.profdata"
      llvm-cov show ./neuropil/bin/neuropil_test_suite -instr-profile="$(pwd)/neuropil_test_suite.profdata"

      # Enable for test debugging
      #nohup ./build/neuropil/bin/neuropil_test_suite --debug=gdb -j1 --xml=neuropil_test_suite-junit.xml "$@" &>/dev/null &
      #sleep 1
      #gdb ./build/neuropil/bin/neuropil_test_suite -ex "target remote localhost:1234" -ex "continue"
    fi
  )
}

task_test() {
  ensure_venv

  task_build --DEBUG tests

  (
    cd build
    mkdir -p logs
    if [[ $? == 0 ]] ; then
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

  echo "./build/neuropil/bin/$application" "$@"
  set +e
  run=$("./build/neuropil/bin/$application" "$@")
  set -e
  if [ "$run" != 0 ] ; then
    gdb "./build/neuropil/bin/$application" -c core*
  fi

}

task_smoke() {
  (
    ensure_venv
    task_install_python

    cd build
    mkdir -p logs

    set +e
    nose2 -v --config ../configs/nose2.cfg "$@"
    e=$?
    if [ e == 139 ] && [ -t 0 ]; then
      read -r -p "${1:-Debug with gdb? [y/N]} " response
      case "$response" in
          [yY][eE][sS]|[yY])
              gdb --silent -ex=r --args nose2 -v --config ../configs/nose2.cfg
              ;;
          *)
              ;;
      esac
    fi
    set -e
    return $e
  )
}
task_helgrind() {
  (
    ensure_venv
    task_install_python

    cd build
    mkdir -p logs

    date > helgrind.log
    set +e
    valgrind --gen-suppressions=all --tool=helgrind --suppressions=../configs/valgrind.supp ../.venv/bin/nose2 --config ../configs/nose2.cfg "$@" |& tee helgrind.log;
    ret=${PIPESTATUS[0]}
    set -e
    return $ret
  )
}

task_ensure_dependencies() {
  ensure_venv

  git submodule update --init --recursive --force
  root="$(pwd)"
  (task_build --RELEASE dependencies)
  echo "installing git hooks"
  mkdir -p .git/hooks
  rm -f .git/hooks/pre-commit
  ln -s .git_hooks/pre-commit .git/hooks/pre-commit

  echo "neuropil development enviroment is ready"
}

task_run_script(){
  ensure_venv
  (
    script=$1
    shift;
    python "scripts/$script" "$@"
  )
}
task_uninstall(){
  sudo rm -rf /usr/local/lib/neuropil*
  sudo rm -rf /usr/local/include/neuropil*
}
task_pre_commit(){
  ensure_venv

  task_build release python
  python3 scripts/util/build_helper.py --update_strings
}
usage() {
  echo "$0  build | test | clean | package | coverage | script | deploy | smoke | doc | (r)un | ensure_dependencies | pre_commit | helgrind | analyze"
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
  pwd=$(pwd)
  criterion_path=($pwd/build/ext_tools/Criterion/usr/local/lib/*/)
  export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$pwd/build/neuropil/lib:$pwd/build/ext_tools/libsodium/lib:$criterion_path"

  case "$cmd" in
    clean) task_clean ;;
    build) task_build "$@";;
    doc) task_doc ;;
    coverage) task_coverage "$@";;
    test) task_test "$@";;
    package) task_package "$@";;
    install_python) task_install_python ;;
    smoke) task_smoke "$@";;
    run) task_run "$@";;
    r) task_run "$@";;
    ensure_dependencies) task_ensure_dependencies;;

    pre_commit) task_pre_commit ;;

    helgrind) task_helgrind "$@";;
    analyze) task_analyze "$@";;
    script) task_run_script "$@";;
    uninstall) task_uninstall "$@";;

    *) usage ;;
  esac
  exit $?
)
