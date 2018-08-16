#! /usr/bin/env python3

import platform
import glob
import io
import os

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

# use clang to compile the source code
default_env = Environment(CC = 'clang')
default_env.VariantDir('build/obj', 'src', duplicate=0)

# read in additional compile flags
analyze = ARGUMENTS.get('analyze', 0)
build_tests = ARGUMENTS.get('test', 1)
build_doc = ARGUMENTS.get('doc', 0)
debug = ARGUMENTS.get('debug', 0)
release = ARGUMENTS.get('release', 0)
console_log = ARGUMENTS.get('console', 0)
strict = int(ARGUMENTS.get('strict', 0))
build_program = ARGUMENTS.get('program', False)
build_x64 = int(ARGUMENTS.get('x64', -1))
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

# add libev flags to the compilation
default_env.Append(CCFLAGS = ['-DEV_STANDALONE'])
# env.Append(CCFLAGS = ['-DEV_PERIODIC_ENABLE'])
default_env.Append(CCFLAGS = ['-DHAVE_SELECT'])
default_env.Append(CCFLAGS = ['-DHAVE_KQUEUE'])
default_env.Append(CCFLAGS = ['-DHAVE_POLL'])
default_env.Append(CCFLAGS = ['-DEV_COMPAT3=0'])
default_env.Append(CCFLAGS = ['-DEV_USE_FLOOR=1'])
# env.Append(CCFLAGS = ['-DEV_USE_REALTIME=0'])
default_env.Append(CCFLAGS = ['-DEV_USE_4HEAP=1'])
# env.Append(CCFLAGS = ['-DEV_NO_THREADS'])



if build_x64:
    default_env.Append(CCFLAGS = ['-Dx64'])
default_env.Append(CCFLAGS = ['-std=c99'])
default_env.Append(LDFLAGS = ['-std=c99'])

# add release compilation options
release_flags = ['-O3','-DRELEASE']
if int(release) >= 1:
    default_env.Append(CCFLAGS = release_flags)

# add debug compilation options
debug_flags = ['-g', '-Wall', '-Wextra', '-gdwarf-2','-O3']
if int(debug) >= 1:
    default_env.Append(CCFLAGS = debug_flags)
    if int(debug) <= 1:
        default_env.Append(CCFLAGS = ['-DDEBUG'])

default_env.Append(CCFLAGS = ['-DNEUROPIL_RELEASE_BUILD=\"{}\"'.format(buildNo())])

if int(console_log):
    default_env.Append(CCFLAGS = ['-DCONSOLE_LOG'])

default_env.Append(LIBS = ['m'])
# platform specific compiler options
if 'FreeBSD' in platform.system():
  default_env.Append(LIBS = ['util','m'] )
  default_env.Append(LIBPATH = ['/usr/local/lib'] )
  default_env.Append(CCFLAGS = ['-I/usr/local/include'] )
if 'Darwin' in platform.system():
  default_env.Append(CCFLAGS = ['-Wno-deprecated'] )
  default_env.Append(CCFLAGS = ['-Wno-nullability-completeness'] )
  default_env.Append(CCFLAGS = ['-Wno-missing-field-initializers'])
  default_env.Append(CCFLAGS = ['-Wno-missing-braces'])
  default_env.Append(CCFLAGS = ['-Wno-unsupported-visibility'] )
  default_env.Append(CCFLAGS = ['-mmacosx-version-min=10.11'] )
  default_env.Append(CCFLAGS = ['-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include'] )
if 'Linux' in platform.system():
  default_env.Append(CCFLAGS = ['-D_GNU_SOURCE'])
  default_env.Append(LIBS = ['rt', 'pthread'] )
  if('arm' in platform.processor()):
    default_env.Append(LIBPATH = ['/usr/lib', '/usr/local/lib','/usr/lib/arm-linux-gnueabihf'] )
    default_env.Append(CCFLAGS = ['-I/usr/include','-I/usr/local/include','-I/usr/include/arm-linux-gnueabihf'] )
if 'CYGWIN' in platform.system():
  # -std=gnu++0x doesn't work, so work around...
  default_env.Append(CCFLAGS = ['-U__STRICT_ANSI__'] )
if 'Windows' in platform.system() or 'OpenBSD' in platform.system():
    default_env.Append(LIBS = ['rt'] )
    default_env.Append(CCFLAGS = ['-x c'])



# env.Append(CCFLAGS = '-march='+platform.processor())
# env.Append(CCFLAGS = '-arch='+platform.machine())
#env.Append(CCFLAGS = '-target ' + platform.machine() + '-' + platform.system().lower() )
# env.Append(CCFLAGS = '-target ' + platform.machine())

print ("continuing with CCFLAGS set to: {dump}".format(dump=default_env.Dump(key='CCFLAGS')) )
print ("continuing with LDFLAGS set to: {dump}".format(dump=default_env.Dump(key='LDFLAGS')) )

print ('####')
print ('#### detecting 3rd party libraries')
print ('####')

default_env.Append(LINKFLAGS = ['-v']) # shows linker invokation

np_include_dir = ['./include']
np_library_dir = ['./build/lib']

default_env.Append(CPPPATH = np_include_dir)
default_env.Append(LIBPATH = np_library_dir)

neuropil_env = default_env.Clone()

# add 3rd party library path info here
tpl_library_list = ['sodium','m']
neuropil_env.Append(LIBS = tpl_library_list)

conf = Configure(neuropil_env)

# Checks for libraries, header files, etc.
for lib in neuropil_env['LIBS']:
    if not conf.CheckLib(lib):
        print ('Did not find library {lib}. Please install the appropiate package. (More information regarding this error may be in "config.log")'.format(lib=lib))
        Exit(1)

if not conf.CheckLibWithHeader('sodium', 'sodium.h', 'c'):
    print ('Did not find libsodium.a or sodium.lib ...')
    Exit(1)

scan_build_exe = neuropil_env.WhereIs('scan-build')
if int(analyze) and not scan_build_exe:
    print ('---')
    print ('did not find clang checker executable in the path, skipping build of static code analysis')
    print ('please consider to install the additional clang static code analysis tool checker (version 278 as of this writing)')
    print ('---')
    Exit(1)

sphinx_exe = neuropil_env.WhereIs('sphinx-build')
if int(build_doc) and not sphinx_exe:
    print ('---')
    print ('did not find sphinx executable in the path, skipping build of documentation')
    print ('---')
    Exit(1)


criterion_is_available = conf.CheckLibWithHeader('criterion', 'criterion/criterion.h', 'c')
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
def build_sphinx_doc(source, target, neuropil_env, for_signature):
    return 'sphinx-build %s %s' % (source[0], target[0])
sphinx_builder = Builder(generator = build_sphinx_doc, target_factory=Dir, source_factory=Dir)
neuropil_env.Append(BUILDERS = {'Sphinx' : sphinx_builder})


if int(build_doc) and sphinx_exe:
    neuropil_env.Sphinx('./build/html', './doc/source')

if int(analyze) and scan_build_exe:
    neuropil_env.Analyzer('build/sca')

# if int(analyze):
#     neuropil_env.Append(CCFLAGS='-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/usr/include')

# sources for neuropil
SOURCES =  ['build/obj/dtime.c','build/obj/np_time.c','build/obj/neuropil.c','build/obj/np_aaatoken.c','build/obj/np_axon.c','build/obj/np_dendrit.c']
SOURCES += ['build/obj/np_glia.c','build/obj/np_http.c','build/obj/np_jobqueue.c','build/obj/np_dhkey.c','build/obj/np_key.c','build/obj/np_keycache.c']
SOURCES += ['build/obj/np_log.c','build/obj/np_memory.c','build/obj/np_message.c','build/obj/np_msgproperty.c','build/obj/np_network.c','build/obj/np_node.c']
SOURCES += ['build/obj/np_route.c','build/obj/np_tree.c','build/obj/np_util.c','build/obj/np_treeval.c','build/obj/np_threads.c','build/obj/np_pinging.c']
SOURCES += ['build/obj/np_sysinfo.c','build/obj/np_scache.c','build/obj/np_event.c','build/obj/np_messagepart.c','build/obj/np_statistics.c','build/obj/np_responsecontainer.c']
SOURCES += ['build/obj/np_serialization.c','build/obj/np_memory_v2.c','build/obj/np_shutdown.c','build/obj/np_identity.c','build/obj/np_token_factory.c']

# source code 3rd party libraries
SOURCES += ['build/obj/event/ev.c', 'build/obj/json/parson.c','build/obj/msgpack/cmp.c','build/obj/gpio/bcm2835.c']

# test cases for neuropil
TESTS =  ['test/test_suites.c']

print ('####')
print ('#### building neuropil libraries/testsuite/example programs:')
print ('####')

# build the neuropil library as static and shared library
np_stlib = neuropil_env.Library('build/lib/neuropil', SOURCES,		 LIBS=tpl_library_list)
np_dylib = neuropil_env.SharedLibrary('build/lib/neuropil', SOURCES, LIBS=tpl_library_list)
#AlwaysBuild(np_dylib)
#AlwaysBuild(np_stlib)

# build test executable
if int(release) < 1 and int(build_tests) > 0 and criterion_is_available:
    print ('Test cases included')
    # include the neuropil build path library infos
    test_env = default_env.Clone()
    test_env.Append(LIBS = ['criterion','neuropil']+tpl_library_list)
    test_suite = test_env.Program('bin/neuropil_test_suite', TESTS)
    Depends(test_suite, np_dylib)
else:
    print ('Test cases not included')

# build example programs
programs = [
    'controller','node','receiver','sender','receiver_cb','pingpong','hydra','shared_hydra',
    'echo_server','echo_client','raspberry','demo_service','test'
    ]
program_env = default_env.Clone()
program_env.Append(LIBS = ['ncurses','neuropil','sodium'])

if build_program != False and build_program not in programs:
    if build_program != 'lib_only':
        print ('desired program {program} does not exist'.format(program=build_program) )
        print ('please select from: {programs}, lib_only'.format(programs=join(programs)) )
else:
    for program in programs:
        if build_program == False or build_program == program:
            print ('building neuropil_{program_name}'.format(program_name=program))
            prg_np = program_env.Program('bin/neuropil_%s'%program, 'examples/neuropil_%s.c'%program)
            Depends(prg_np, np_dylib)


prg_np = program_env.Program('bin/pilarnet', 'examples/workshop/pilarnet.c')
Depends(prg_np, np_dylib)

# clean up
Clean('.', 'build')
Clean('.', 'bin')
Clean('.', 'warn.log')
Clean('.', 'warn_clean.log')

print ("build with:")
print ("analyze       =  %r" % analyze)
print ("build_tests   =  %r" % build_tests)
print ("build_doc     =  %r" % build_doc)
print ("debug         =  %r" % debug)
print ("release       =  %r" % release)
print ("console_log   =  %r" % console_log)
print ("strict        =  %r" % strict)
print ("build_program =  %r" % build_program)
print ("build_x64     =  %r" % build_x64)
