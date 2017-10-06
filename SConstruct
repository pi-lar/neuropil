
import platform


print '####'
print '#### starting neuropil build'
print '####'
print 'building on : ' + str(platform.machine()) + '/' + str(platform.processor()) + '/' + str(platform.system())

# building on : x86_64/i386/Darwin
# TARGET=x86_64-apple-darwin-macho

# use clang to compile the source code
env = Environment(CC = 'clang')
env.VariantDir('build/obj', 'src', duplicate=0)

# read in additional compile flags
analyze = ARGUMENTS.get('analyze', 0)
build_tests = ARGUMENTS.get('test', 1)
build_doc = ARGUMENTS.get('doc', 0)
debug = ARGUMENTS.get('debug', 0)
release = ARGUMENTS.get('release', 0)
console_log = ARGUMENTS.get('console', 0)
strict = int(ARGUMENTS.get('strict', 0))
build_program = ARGUMENTS.get('program', False)


print '####'
print '#### adding compiler options and flags'
print '####'

if strict:
    env.Append(CCFLAGS = ['-DSTRICT'])

# add libev flags to the compilation
env.Append(CCFLAGS = ['-DEV_STANDALONE'])
env.Append(CCFLAGS = ['-DEV_PERIODIC_ENABLE'])
env.Append(CCFLAGS = ['-DHAVE_SELECT'])
env.Append(CCFLAGS = ['-DHAVE_KQUEUE'])
env.Append(CCFLAGS = ['-DHAVE_POLL'])

env.Append(CCFLAGS = ['-std=c99'])
env.Append(LDFLAGS = ['-std=c99'])

# add release compilation options
release_flags = ['-O3',]
if int(release):
    env.Append(CCFLAGS = release_flags)

# add debug compilation options
debug_flags = ['-g', '-Wall', '-Wextra', '-gdwarf-2']
if int(debug):
    env.Append(CCFLAGS = debug_flags)
    env.Append(CCFLAGS = ['-DDEBUG'])
if int(console_log):
    env.Append(CCFLAGS = ['-DCONSOLE_LOG'])


# platform specific compiler options
if 'FreeBSD' in platform.system():
  env.Append(LIBS = ['util','m'] )
  env.Append(LIBPATH = ['/usr/local/lib'] )
  env.Append(CCFLAGS = ['-I/usr/local/include'] )
if 'Darwin' in platform.system():
  env.Append(CCFLAGS = ['-Wno-deprecated'] )
  env.Append(CCFLAGS = ['-mmacosx-version-min=10.11'] )
  env.Append(CCFLAGS = ['-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include'] )
if 'Linux' in platform.system():
  env.Append(CCFLAGS = ['-D_GNU_SOURCE'])
  env.Append(LIBS = ['rt', 'pthread'] )
  if('arm' in platform.processor()):
    env.Append(LIBPATH = ['/usr/lib', '/usr/local/lib','/usr/lib/arm-linux-gnueabihf'] )
    env.Append(CCFLAGS = ['-I/usr/include','-I/usr/local/include','-I/usr/include/arm-linux-gnueabihf'] )
if 'CYGWIN' in platform.system():
  # -std=gnu++0x doesn't work, so work around...
  env.Append(CCFLAGS = ['-U__STRICT_ANSI__'] )
if 'Windows' in platform.system() or 'OpenBSD' in platform.system():
    env.Append(LIBS = ['rt'] )
    env.Append(CCFLAGS = ['-x c'])


# env.Append(CCFLAGS = '-march='+platform.processor())
# env.Append(CCFLAGS = '-arch='+platform.machine())
#env.Append(CCFLAGS = '-target ' + platform.machine() + '-' + platform.system().lower() )
# env.Append(CCFLAGS = '-target ' + platform.machine())

print 'continuing with CCFLAGS set to: ' + env.Dump(key='CCFLAGS')
print 'continuing with LDFLAGS set to: ' + env.Dump(key='LDFLAGS')

print '####'
print '#### detecting 3rd party libraries'
print '####'

env.Append(LINKFLAGS = ['-v']) # shows linker invokation

# add 3rd party library path info here
tpl_library_list = ['sodium']
env.Append(LIBS = tpl_library_list)

conf = Configure(env)

# Checks for libraries, header files, etc.
for lib in env['LIBS']:
    if not conf.CheckLib(lib):
        print 'Did not find library %s. Please install the appropiate package' % (lib)
        Exit(1)

if not conf.CheckLibWithHeader('sodium', 'sodium.h', 'c'):
    print 'Did not find libsodium.a or sodium.lib ...'
    Exit(1)

if int(release) < 1 and int(build_tests) > 0 and conf.CheckLibWithHeader('criterion', 'criterion/criterion.h', 'c'):
    print 'Test cases included'
    tpl_library_list += ['criterion']
    env.Append(LIBS = tpl_library_list)
else:
    print 'Test cases not included'
    build_tests = 0

print '####'
print '#### adding neuropil specific build path informations'
print '####'

# include the neuropil build path library infos
np_library     = ['neuropil']
np_include_dir = ['./include']
np_library_dir = ['./build/lib']

env.Append(CPPPATH = np_include_dir)
env.Append(LIBPATH = np_library_dir)
env.Append(LIBS = np_library)

scan_build_exe = env.WhereIs('scan-build')
if int(analyze) and not scan_build_exe:
    print '---'
    print 'did not find clang checker executable in the path, skipping build of static code analysis'
    print 'please consider to install the additional clang static code analysis tool checker (version 278 as of this writing)'
    print '---'
    Exit(1)

sphinx_exe = env.WhereIs('sphinx-build')
if int(build_doc) and not sphinx_exe:
    print '---'
    print 'did not find sphinx executable in the path, skipping build of documentation'
    print '---'
    Exit(1)

env = conf.Finish()

# create an own builder to do clang static source code analyisis
# TODO: not yet working
# analyzer_flags = ['--analyze', '-Xanalyzer', '-analyzer-config', '-analyzer-checker=alpha.security', '-analyzer-checker=alpha.core', '-analyzer-output=html']
# analyzer_flags = ['--analyze', '-Xanalyzer', '-analyzer-checker=alpha.security', '-analyzer-checker=alpha.core', '-analyzer-output=html']
def analyze_source_code(source, target, env, for_signature):
           return 'scan-build make -o %s' % ( target[0] )
analyze_builder = Builder(generator = analyze_source_code)
env.Append(BUILDERS = {'Analyzer' : analyze_builder})

# create sphinx builder, hopefully sphinx-build will be on the path
def build_sphinx_doc(source, target, env, for_signature):
    return 'sphinx-build %s %s' % (source[0], target[0])
sphinx_builder = Builder(generator = build_sphinx_doc, target_factory=Dir, source_factory=Dir)
env.Append(BUILDERS = {'Sphinx' : sphinx_builder})


if int(build_doc) and sphinx_exe:
    env.Sphinx('./build/html', './doc/source')

if int(analyze) and scan_build_exe:
    env.Analyzer('build/sca')

# if int(analyze):
#     env.Append(CCFLAGS='-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/usr/include')

# sources for neuropil
SOURCES =  ['build/obj/dtime.c','build/obj/neuropil.c','build/obj/np_aaatoken.c','build/obj/np_axon.c','build/obj/np_dendrit.c']
SOURCES += ['build/obj/np_glia.c','build/obj/np_http.c','build/obj/np_jobqueue.c','build/obj/np_dhkey.c','build/obj/np_key.c','build/obj/np_keycache.c']
SOURCES += ['build/obj/np_log.c','build/obj/np_memory.c','build/obj/np_message.c','build/obj/np_msgproperty.c','build/obj/np_network.c','build/obj/np_node.c']
SOURCES += ['build/obj/np_route.c','build/obj/np_tree.c','build/obj/np_util.c','build/obj/np_treeval.c','build/obj/np_threads.c']
SOURCES += ['build/obj/np_sysinfo.c','build/obj/np_scache.c','build/obj/np_event.c','build/obj/np_messagepart.c','build/obj/np_statistics.c']
# source code 3rd party libraries
SOURCES += ['build/obj/event/ev.c', 'build/obj/json/parson.c','build/obj/msgpack/cmp.c','build/obj/gpio/bcm2835.c']

# test cases for neuropil
TESTS =  ['test/test_suites.c']

print '####'
print '#### building neuropil libraries/testsuite/example programs:'
print '####'
# build the neuropil library as static and shared library

np_stlib = env.Library('build/lib/neuropil', SOURCES, LIBS=tpl_library_list)
np_dylib = env.SharedLibrary('build/lib/neuropil', SOURCES, LIBS=tpl_library_list)
AlwaysBuild(np_dylib)
AlwaysBuild(np_stlib)

# build test executable
if int(build_tests):
    test_suite = env.Program('bin/neuropil_test_suite', TESTS)
    Depends(test_suite, np_dylib)
    AlwaysBuild(test_suite)

# build example programs
programs = [
    'controller','node','receiver','sender','receiver_cb','pingpong','hydra','shared_hydra',
    'echo_server','echo_client','raspberry','demo_service'
    ]
if build_program != False and build_program not in programs:
    if build_program != 'lib_only':
        print 'desired program %s does not exist' % build_program
        print 'please select from: %s, lib_only' % ', '.join(programs)
else:
    for program in programs:
        if build_program == False or build_program == program:
            prg_np = env.Program('bin/neuropil_%s'%program, 'examples/neuropil_%s.c'%program)
            Depends(prg_np, np_dylib)
            print 'build'

# clean up
Clean('.', 'build')
Clean('.', 'bin')
