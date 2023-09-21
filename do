#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

# colorcodes https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux
RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

set -eu

ensure_venv() {
  if [ ! -d .venv ]; then
    $(which python3) -m venv .venv
    ./.venv/bin/pip3 install --upgrade pip
    ./.venv/bin/pip3 install --upgrade setuptools
    ./.venv/bin/pip3 install --upgrade wheel
    ./.venv/bin/pip3 install -r configs/requirements.txt
  fi

  if [ configs/requirements.txt -nt .venv ]; then
    ./.venv/bin/pip3 install --upgrade pip
    ./.venv/bin/pip3 install --upgrade setuptools
    ./.venv/bin/pip3 install --upgrade wheel
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

  warnings=$( echo "$unsorted" | grep ': warning:'                                                                     |sort|grep -v "/event/"|uniq)
    errors=$( echo "$unsorted" | grep ': error:\|scons: building terminated because of errors\|undefined reference to' |sort|grep -v "/event/"|uniq)

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

task_tidy() {
  ensure_venv
  ret=-1
  (
    rm -rf build/tidy*
    set +e
    find src/ -iname '*.c' | xargs -i clang-tidy --warnings-as-errors="*" {} -- -Iinclude -Iext_tools -Iframework -Ibuild/ext_tools/libsodium/include -std=gnu99 | tee build/tidy.log
    ret=${PIPESTATUS[1]}
    grep ": error: " build/tidy.log > build/tidy-clean.log
    echo "Total issues: $(cat build/tidy-clean.log | wc -l)"
    ret=$?
    set -e
  )
  return $ret
}



_task_format() {
  local ret=0
  local doEcho=$1
  shift;
   
  shopt -s globstar;
  tmpfile=$(mktemp /tmp/clang-format-test.XXXXXX)
  clang-format-14 --style=filse $@ "$tmpfile"
  rm "$tmpfile"
  
  set +e
  rm -rf build/format*;
  touch build/format.log
  files=()
  files+="$(find ./framework -type f -iname *.h -o -iname *.c | paste -d ' ') "
  files+="$(find ./examples -type f -iname *.h -o -iname *.c | paste -d ' ') "
  files+="$(find ./include -type f -iname *.h -o -iname *.c | paste -d ' ') "
  files+="$(find ./src -type f -iname *.h -o -iname *.c | paste -d ' ') "
  files=$(echo $files  )

  clang-format-14 --style=file $@ $files 2>&1 | tee -a build/format.log
  
  grep ": warning: " build/format.log > build/format-warnings-clean.log
  warnings=$(cat build/format-warnings-clean.log | sort | uniq | wc -l);
  cat build/format-warnings-clean.log | sort | uniq > build/format-warnings-clean.log
  grep ": error: " build/format.log > build/format-errors-clean.log
  cat build/format-errors-clean.log | sort | uniq > build/format-errors-clean.log
  errors=$(cat build/format-errors-clean.log  | wc -l);
  set -e

  sum=($warnings + $errors);
  if [ "$doEcho" == "true" ]
  then
    printf "    Warnings: %6d\n" "$warnings"
    printf "      Errors: %6d\n" "$errors"
    printf "Total issues: %6d\n" "$sum"
  fi
  if [ $errors -gt 0 ]
  then
    ret=1
  fi
  if [ $sum -gt 0 ]
  then
    ret=2
  fi
  
  return $ret
}

task_pipeline_format() {
  _task_format true --dry-run $@
  return "$?"
}

task_format() {
  set +e
  task_pipeline_format $@
  local ret=$?
  set -e

  echo "task_pipeline_format: $ret"
  if [ $ret -ne 0 ]
  then
    echo -n "Correcting now ..."
    _task_format false -i $@
    echo " done"
  fi
  return "$?"
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
      # Enable for test debugging
      if [ "0" = 1 ] ; then
        nohup ./neuropil/bin/neuropil_test_suite --debug=gdb -j1 --xml=neuropil_test_suite-junit.xml "$@" &>/dev/null &
        sleep 1
        gdb ./neuropil/bin/neuropil_test_suite -ex "target remote localhost:1234" -ex "continue"
      else
        ./neuropil/bin/neuropil_test_suite -j1 --xml=neuropil_test_suite-junit.xml "$@"
      fi
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
  (
    cd build
    
    echo "./neuropil/bin/$application" "$@"
    set +e
    "./neuropil/bin/$application" "$@"
    run=$?
    set -e
    if [ "$run" != 0 ] ; then
      reset
      gdb "./neuropil/bin/$application" -c core*
    fi
  )

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
task_callgrind() {
  (
    ensure_venv
    task_install_python

    cd build
    mkdir -p logs

    date > callgrind.log
    set +e
    valgrind --tool=callgrind  --callgrind-out-file=callgrind.out --suppressions=../configs/valgrind.supp ../.venv/bin/nose2 --config ../configs/nose2.cfg test_pub_sub "$@" |& tee callgrind.log;
    ret=${PIPESTATUS[0]}
    gprof2dot --format=callgrind --output=callgrind.dot callgrind.out
    dot -Tpng callgrind.dot -o callgrind.png
    set -e
    callgrind_annotate --show-percs=yes --include=include callgrind.out | grep "libneuropil.so"
    return $ret
  )
}
task_valgrind() {
  (
    ensure_venv
    task_install_python

    cd build
    mkdir -p logs

    date > valgrind.log
    set +e
    valgrind  --gen-suppressions=all --leak-check=full --show-leak-kinds=all --track-origins=yes --suppressions=../configs/valgrind.supp ../.venv/bin/nose2 --config ../configs/nose2.cfg "$@" |& tee valgrind.log;
    ret=${PIPESTATUS[0]}
    set -e
    return $ret
  )
}
task_gdb() {
  (
    ensure_venv

    gdb -c $1 build/neuropil/lib/libneuropil.so

    return 0
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
task_run_bin(){
  ensure_venv
  (
    "$@"
  )
}
task_uninstall(){
  sudo rm -rf /usr/local/lib/*neuropil*
  sudo rm -rf /usr/local/include/neuropil*
}
task_pre_commit(){
  ensure_venv

  task_format;
  python3 scripts/util/build_helper.py --update_strings;
}
task_search_log(){
  grep --no-filename "$@" build/logs/* | sort -k2
}
task_grep() {
  grep --with-filename "$@" | sort -k2,3 | ccze -A | less -S
  return $?
}
usage() {
  echo "$0  build | test | clean | package | coverage | script | deploy | smoke | doc | (r)un | ensure_dependencies | pre_commit | helgrind | analyze | gdb | grep"
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

    log) task_search_log "$@";;
    gdb) task_gdb "$@";;
    helgrind) task_helgrind "$@";;
    valgrind) task_valgrind "$@";;
    callgrind) task_callgrind "$@";;    
    analyze) task_analyze "$@";;
    tidy) task_tidy "$@";;
    format) task_format "$@";;
    pipeline_format) task_pipeline_format "$@";;
    script) task_run_script "$@";;
    bin) task_run_bin "$@";;
    uninstall) task_uninstall "$@";;

    grep) task_grep "$@";;
    g) task_grep "$@";;

    *) usage ;;
  esac
  exit "$?"
)
