#! /usr/bin/env python3

# 
# neuropil is copyright 2016-2019 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
# 

import subprocess
import platform
import glob
import io
import os
import SCons.Util

def exec_call(target):        
    ret = subprocess.check_call(target)
    if ret != 0:        
        print("Error: cannot execute {target}".format(**locals()))
    return ret

def SymLink(target, source, env):
    os.symlink(os.path.abspath(str(source[0])), os.path.abspath(str(target[0])))

def buildNo():
    try:
      f = open('.buildno', 'r+')
    except:
      f = open('.buildno', 'w+')

    buildno = f.read()
    if buildno == "":
        buildno = 1;
    else:
        buildno = int(buildno) + 1
    f.seek(0)
    f.write(str(buildno))
    f.truncate()
    f.close()

    return buildno


print ('####')
print ('#### starting neuropil build')
print ('####')
print ('building on: {platform} / {processor} / {system}'.format(platform=str(platform.machine()), processor=str(platform.processor()), system=str(platform.system())) )

try:
    import multiprocessing
    SetOption('num_jobs', multiprocessing.cpu_count())
except:
    pass;


verbose = bool(ARGUMENTS.get('verbose', 1))
analyze = ARGUMENTS.get('analyze', 0)
build_tests = int(ARGUMENTS.get('test', 1))
build_tests_enable_test_coverage = build_tests > 1
build_doc = int(ARGUMENTS.get('doc', 0))
debug = ARGUMENTS.get('debug', 0)
release = ARGUMENTS.get('release', 0)
console_log = ARGUMENTS.get('console', 0)
strict = int(ARGUMENTS.get('strict', 0))
build_program = ARGUMENTS.get('program', False)
opt_debug_optimization_level = ARGUMENTS.get('dO', 0)
build_x64 = int(ARGUMENTS.get('x64', -1))
install = int(ARGUMENTS.get('install', 0))
build_bindings = bool(int(ARGUMENTS.get('bindings', False)))
build_bindings_lua = bool(int(ARGUMENTS.get('lua_binding', build_bindings)))
build_bindings_python = bool(int(ARGUMENTS.get('python_binding', build_bindings)))


# use clang to compile the source code
if build_tests_enable_test_coverage:
    '''
    default_env = Environment(CC = 'gcc', tools = ['default', 'gcccov'])
    # Generate correct dependencies of `*.gcno' and `*.gcda' files on object
    # files being built from now on.
    default_env.GCovInjectObjectEmitters()
    default_env.Append(CCFLAGS = ['-g', '-O0', '--coverage'], LDFLAGS = ['--coverage'], LIBS="gcov")
    '''
    default_env = Environment(CC = 'gcc')
    default_env.Append(CCFLAGS = ['-g', '-O0', '--coverage','-fprofile-arcs','-ftest-coverage'], LDFLAGS = ['--coverage'], LIBS="gcov") 
else:
    default_env = Environment(CC = 'clang')



if 'TERM' in os.environ:
  default_env['ENV']['TERM'] = os.environ['TERM']

if os.getenv("CC"):
    default_env["CC"] = os.getenv("CC")
default_env["CXX"] = os.getenv("CXX")
default_env["ENV"].update(x for x in os.environ.items() if x[0].startswith("CCC_"))

variantDir = 'build/obj/'

default_env.VariantDir(variantDir+'framework', 'framework', duplicate=0)
default_env.VariantDir(variantDir+'src', 'src', duplicate=0)
default_env.VariantDir(variantDir+'test', 'test', duplicate=0)
default_env.VariantDir(variantDir+'examples', 'examples', duplicate=0)

default_env.Decider('MD5')


# read in additional compile flags


if build_x64 == -1:
    build_x64  = "64" in str(platform.processor())
else:
    build_x64 = build_x64 == True  # normalize
    if build_x64 == True and "64" not in str(platform.processor()):
        print ('ERROR: x64 build on x86 system!')

print ('####')
print ('#### adding compiler options and flags')
print ('####')

if strict:
    default_env.Append(CCFLAGS = ['-DSTRICT'])

if build_x64:
    default_env.Append(CCFLAGS = ['-Dx64'])
default_env.Append(CCFLAGS = ['-std=c99'])
default_env.Append(LDFLAGS = ['-std=c99'])

# add release compilation options
release_flags = ['-O3','-DRELEASE']
if int(release) >= 1:
    default_env.Append(CCFLAGS = release_flags)

# add debug compilation options
debug_flags = ['-g', '-Wall', '-Wextra', '-gdwarf-2','-O'+str(opt_debug_optimization_level)]

if int(debug) >= 1:
  default_env.Append(CCFLAGS = debug_flags)
  if int(debug) <= 1:
    default_env.Append(CCFLAGS = ['-DDEBUG'])

if int(console_log):
    default_env.Append(CCFLAGS = ['-DCONSOLE_LOG'])


# platform specific compiler options

if 'FreeBSD' in platform.system():
  default_env.Append(LIBS = ['util', 'm'] )
  default_env.Append(LIBPATH = ['/usr/local/lib'] )
  default_env.Append(CPPPATH = ['/usr/local/include'] )


if 'Darwin' in platform.system():
  # default_env.Append(CCFLAGS = ['-Wformat-security'])
  # default_env.Append(CCFLAGS = ['-fstack-protector-all'])
  # default_env.Append(CCFLAGS = ['-Wstrict-overflow'])
  default_env.Append(CCFLAGS = ['-fno-omit-frame-pointer'])
  default_env.Append(CCFLAGS = ['-Wno-nullability-completeness'])
  default_env.Append(CCFLAGS = ['-Wno-missing-field-initializers'])
  default_env.Append(CCFLAGS = ['-Wno-missing-braces'])
  default_env.Append(CCFLAGS = ['-Wno-unsupported-visibility'])
  default_env.Append(CCFLAGS = ['-mmacosx-version-min=10.11'])
  default_env.Append(CPPPATH = ['/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include'] )

if 'Linux' in platform.system():
  default_env.Append(LIBS = ['m'])
  default_env.Append(CCFLAGS = ['-D_GNU_SOURCE'])
  default_env.Append(LIBS = ['rt', 'pthread'] )

  if('arm' in platform.processor()):
    default_env.Append(LIBPATH = ['/usr/lib', '/usr/local/lib','/usr/lib/arm-linux-gnueabihf'] )
    default_env.Append(CPPPATH = ['/usr/include','/usr/local/include','/usr/include/arm-linux-gnueabihf'] )

if 'CYGWIN' in platform.system():
  # -std=gnu++0x doesn't work, so work around...
  default_env.Append(CCFLAGS = ['-U__STRICT_ANSI__'] )

if 'Windows' in platform.system() or 'OpenBSD' in platform.system():
    default_env.Append(LIBS = ['rt'] )
    default_env.Append(CCFLAGS = ['-x c'])

# env.Append(CCFLAGS = '-march='+platform.processor())
# env.Append(CCFLAGS = '-arch='+platform.machine())
# env.Append(CCFLAGS = '-target ' + platform.machine() + '-' + platform.system().lower() )
# env.Append(CCFLAGS = '-target ' + platform.machine())

if verbose:
    default_env.Append(LINKFLAGS = ['-v']) # shows linker invokation

default_env.Append(CPPPATH = ['./include','./framework'])
default_env.Append(LIBPATH = ['./build/lib'])

print ("continuing with CCFLAGS set to: {dump}".format(dump=default_env.Dump(key='CCFLAGS')) )
print ("continuing with LDFLAGS set to: {dump}".format(dump=default_env.Dump(key='LDFLAGS')) )

print ('####')
print ('#### detecting 3rd party libraries')
print ('####')
neuropil_env = default_env.Clone()

# add 3rd party library path info here
neuropil_env.Append(LIBS = ['sodium'])
if 'Windows' in platform.system():
    neuropil_env.Append(LIBPATH = ['./ext_tools/libsodium/win32'])

conf = Configure(neuropil_env)



# add libev flags to the compilation
neuropil_env.Append(CCFLAGS = ['-DEV_STANDALONE'])
# env.Append(CCFLAGS = ['-DEV_PERIODIC_ENABLE'])
#neuropil_env.Append(CCFLAGS = ['-DEV_USE_SELECT=1'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_SELECT'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_KQUEUE'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_POLL'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_EPOLL_CTL'])
neuropil_env.Append(CCFLAGS = ['-DEV_COMPAT3=0'])
neuropil_env.Append(CCFLAGS = ['-DEV_USE_FLOOR=1'])
neuropil_env.Append(CCFLAGS = ['-DEV_USE_4HEAP=1'])
if conf.CheckFunc('nanosleep'):
    neuropil_env.Append(CCFLAGS = ['-DEV_USE_NANOSLEEP=1'])
# neuropil_env.Append(CCFLAGS = ['-DEV_USE_REALTIME=0'])
# neuropil_env.Append(CCFLAGS = ['-DEV_NO_THREADS'])

# Checks for libraries, header files, etc.
for lib in neuropil_env['LIBS']:
    if not conf.CheckLib(lib):
        print ('Did not find library {lib}. Please install the appropiate package. (More information regarding this error may be in "config.log")'.format(lib=lib))
        Exit(1)

if not conf.CheckLibWithHeader('sodium', 'sodium.h', 'c'):
    print ('Did not find libsodium.so or sodium.lib ...')
    Exit(1)

scan_build_exe = neuropil_env.WhereIs('scan-build') or SCons.Util.WhereIs('scan-build')
if int(analyze) and not scan_build_exe:
    print ('---')
    print ('did not find clang checker executable in the path, skipping build of static code analysis')
    print ('please consider to install the additional clang static code analysis tool checker (version 278 as of this writing)')
    print ('---')
    Exit(1)

sphinx_exe = neuropil_env.WhereIs('sphinx-build') or SCons.Util.WhereIs('sphinx-build')
if build_doc and not sphinx_exe:
    print ('---')
    print ('did not find sphinx executable in the path, skipping build of documentation')
    print ('---')
    Exit(1)

neuropil_env = conf.Finish()

# create an own builder to do clang static source code analyisis
# TODO: not yet working
# analyzer_flags = ['--analyze', '-Xanalyzer', '-analyzer-config', '-analyzer-checker=alpha.security', '-analyzer-checker=alpha.core', '-analyzer-output=html']
# analyzer_flags = ['--analyze', '-Xanalyzer', '-analyzer-checker=alpha.security', '-analyzer-checker=alpha.core', '-analyzer-output=html']
def analyze_source_code(source, target, neuropil_env, for_signature):
           return 'scan-build make -o %s' % ( target[0] )
analyze_builder = Builder(generator = analyze_source_code)
neuropil_env.Append(BUILDERS = {'Analyzer' : analyze_builder})

# create sphinx builder, hopefully sphinx-build will be on the path
#def build_sphinx_doc(source, target, neuropil_env, for_signature):
#    return 'sphinx-build %s %s' % (source[0], target[0])
#sphinx_builder = Builder(generator = build_sphinx_doc, target_factory=Dir, source_factory=Dir)
#neuropil_env.Append(BUILDERS = {'Sphinx' : sphinx_builder})

if build_doc and sphinx_exe:
    #neuropil_env.Sphinx('./build/html', './doc/source')
    compile_documentation = neuropil_env.Command("compile.documentation", None, lambda target,source,env: exec_call('make html -C doc BUILDDIR=../build'.split(' ')))

if int(analyze) and scan_build_exe:
    neuropil_env.Analyzer('build/sca')

# if int(analyze):
#     neuropil_env.Append(CPPPATH='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/usr/include')

# sources for neuropil
SOURCES =  ['dtime.c',      'np_time.c',            'neuropil.c',       'np_aaatoken.c',        'np_axon.c',        'np_dendrit.c']
SOURCES += ['np_glia.c',    'np_jobqueue.c',        'np_dhkey.c',       'np_key.c',             'np_keycache.c',    'np_bootstrap.c']
SOURCES += ['np_log.c',     'np_memory.c',          'np_message.c',     'np_msgproperty.c',     'np_network.c',     'np_node.c']
SOURCES += ['np_route.c',   'np_tree.c',            'np_util.c',        'np_treeval.c',         'np_threads.c',     'np_pinging.c']
SOURCES += ['np_sysinfo.c', 'np_scache.c',          'np_event.c',       'np_messagepart.c',     'np_statistics.c',  'np_responsecontainer.c']
SOURCES += ['np_legacy.c',  'np_serialization.c',   'np_shutdown.c',    'np_token_factory.c',   'np_crypto.c']

SOURCES += ['../framework/prometheus/prometheus.c']

# source code 3rd party libraries
SOURCES += ['event/ev.c', 'json/parson.c','msgpack/cmp.c','gpio/bcm2835.c']

SOURCES = [variantDir + "src/" + s for s in SOURCES]

print ('####')
print ('#### building neuropil libraries/testsuite/example programs:')
print ('####')

# build the neuropil library as static and shared library
if not build_tests_enable_test_coverage:
    np_stlib = neuropil_env.Library('build/lib/neuropil', SOURCES)
np_dylib = neuropil_env.SharedLibrary('build/lib/neuropil', SOURCES)

bindings_python_build = False
if build_bindings_lua:
  bindings_lua_env = default_env.Clone()    
  bindings_lua_build= bindings_lua_env.Command ("build.binding_lua", None, lambda target,source,env: exec_call(['./bindings/luajit/build.sh']))
  Depends(bindings_lua_build, np_dylib)

if build_bindings_python:
  bindings_py_env = default_env.Clone()    
  bindings_python_build= bindings_py_env.Command ("build.binding_python", None, lambda target,source,env: exec_call(['./bindings/python_cffi/build.sh']))
  Depends(bindings_python_build, np_dylib)


test_env = default_env.Clone()
conf = Configure(test_env)
criterion_is_available = conf.CheckLibWithHeader('criterion', 'criterion/criterion.h', 'c')
test_env = conf.Finish()

# build test executable
if int(release) < 1 and int(build_tests) > 0 and criterion_is_available:    
    print ('Test cases included')
    # include the neuropil build path library infos
    test_env.Append(LIBS = ['criterion', 'sodium','ncurses','neuropil'])
    test_suite = test_env.Program('bin/neuropil_test_suite',    variantDir+'test/test_suite.c')
    Depends(test_suite, np_dylib)    
    test_suite = test_env.Program('bin/neuropil_test_units',     variantDir+'test/test_units.c')
    Depends(test_suite, np_dylib)
else:
    print ('Test cases not included')

# build example programs
programs = [
#    (PROGRAM_NAME (w/o neuropil_ prefix), DEPENDENCIES)
    ('controller',     ['neuropil']),
    ('receiver',       ['neuropil']),
    ('sender',         ['neuropil']),
    ('node',           ['neuropil','ncurses','sodium']),
    ('receiver_lb',     ['neuropil','ncurses','sodium']),
    ('cloud',          ['neuropil','ncurses','sodium']),
    ('hydra',          ['neuropil','ncurses','sodium']),
    ('receiver_cb',    ['neuropil','ncurses','sodium']),
    ('pingpong',       ['neuropil','ncurses','sodium']),
    ('echo_server',    ['neuropil','ncurses','sodium']),
    ('echo_client',    ['neuropil','ncurses','sodium']),
    ('raspberry',      ['neuropil','ncurses','sodium']),
    ('demo_service',   ['neuropil','ncurses','sodium']),
    ('raffle',         ['neuropil','ncurses','sodium','sqlite3']),
    ]

if build_program and build_program not in programs:
    if build_program != 'lib_only':
        print ('desired program {program} does not exist'.format(program=build_program) )
        print ('please select from: {programs}, lib_only'.format(programs=join(programs)) )
else:
    for program, libs in programs:
        program_env = default_env.Clone()
        program_env.Append(LIBS = libs)
        if not build_program or build_program == program:
            print ('building neuropil_{program_name}'.format(program_name=program))
            prg_np = program_env.Program('bin/neuropil_%s'%program, variantDir+'examples/neuropil_%s.c'%program)
            Depends(prg_np, np_dylib)


if install:
    install_lib = neuropil_env.Command("install.sharedlib", None, lambda target,source,env: exec_call('sudo ./install.py'.split(' ')))
    Depends(install_lib, np_dylib)
    
    if bindings_python_build:        
        py_install = bindings_py_env.Command("install.binding_python", None, lambda target,source,env: exec_call('./bindings/python_cffi/setup.py install --force'.split(' ')))
        Depends(py_install, install_lib)
        Depends(py_install, bindings_python_build)

# clean up
Clean('.', os.path.join('bindings','luajit','build'))
Clean('.', os.path.join('bindings','python_cffi','build'))
Clean('.', os.path.join('doc','build'))
Clean('.', 'build')
Clean('.', os.path.join('bindings','python_cffi','dist'))
Clean('.', 'dist')
Clean('.', os.path.join('bindings','python_cffi','.eggs'))
Clean('.', '.eggs')
Clean('.', 'bin')
Clean('.', 'warn.log')
Clean('.', 'warn_clean.log')

print ("build with:")
print ("analyze                  =  %r" % analyze)
print ("build_tests              =  %r" % build_tests)
print ("build_doc                =  %r" % build_doc)
print ("debug                    =  %r" % debug)
print ("release                  =  %r" % release)
print ("console_log              =  %r" % console_log)
print ("strict                   =  %r" % strict)
print ("build_program            =  %r" % build_program)
print ("build_x64                =  %r" % build_x64)
print ("enable_test_coverage     =  %r" % build_tests_enable_test_coverage)

