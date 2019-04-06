PLATFORM ?= $(shell uname -s)

CC=clang
# CC=./checker-277/libexec/ccc-analyzer
# CC=/usr/local/Cellar/llvm/7.0.1/bin/clang

# CFLAGS=-c -Wall -O3 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
CFLAGS = -c -Wall -Wextra -g -gdwarf-2 -std=c99 -O1 -DDEBUG -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
# CFLAGS+=--analyze -Xanalyzer -analyzer-config -analyzer-checker=alpha.secure -anaylyzer-checker=alpha.core -analyzer-output=html -o build/html
# CFLAGS=-c -Wall -Wextra -pedantic -g -std=c99
# CFLAGS=-c -O3 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
LDFLAGS=

CLANG_SANITIZER=-fsanitize=fuzzer,address -fno-omit-frame-pointer -fprofile-instr-generate 

ifneq (,$(findstring FreeBSD, $(PLATFORM)))
  override LDFLAGS+=-lutil
else ifneq (,$(findstring Darwin, $(PLATFORM)))
  override CFLAGS+=-Wno-deprecated
  override LDFLAGS+=-framework CoreServices -Wno-deprecated
  override CLANG_SANITIZER+=-mmacosx-version-min=10.14
else ifneq (,$(findstring CYGWIN, $(PLATFORM)))
  # -std=gnu++0x doesn't work, so work around...
  override CXXFLAGS+=-U__STRICT_ANSI__
else

ifeq (,$(findstring Windows, $(PLATFORM)))
ifeq (,$(findstring OpenBSD, $(PLATFORM)))
  override LDFLAGS+=-lrt
endif
endif

endif

# adjust these settings to your location of libsodium and libcriterion
INCLUDES=-I./framework -I./include -I/usr/local/include -I./tpl/criterion-v2.3.2/include

SODIUM_LIBRARIES=-L/usr/local/lib -lsodium
CRITERION_LIBRARIES=-L./tpl/criterion-v2.3.2/lib -lcriterion
NCURSES_LIBRARIES=-L/usr/local/lib -lncurses

TARGET=x86_64-apple-darwin-macho
# TARGET=x86_64-pc-gnu-elf

SOURCES_LIB  = src/dtime.c src/neuropil.c src/np_aaatoken.c src/np_axon.c src/np_bootstrap.c src/np_dendrit.c src/np_crypto.c
SOURCES_LIB += src/np_dhkey.c src/np_event.c src/np_glia.c src/np_jobqueue.c src/np_key.c src/np_keycache.c src/np_legacy.c
SOURCES_LIB += src/np_log.c src/np_memory.c src/np_message.c src/np_messagepart.c src/np_msgproperty.c src/np_network.c
SOURCES_LIB += src/np_node.c src/np_pinging.c src/np_responsecontainer.c src/np_route.c src/np_scache.c src/np_serialization.c src/np_shutdown.c src/np_statistics.c
SOURCES_LIB += src/np_sysinfo.c src/np_threads.c src/np_time.c src/np_token_factory.c src/np_tree.c src/np_treeval.c src/np_util.c
SOURCES_LIB += src/event/ev.c src/gpio/bcm2835.c  src/json/parson.c src/msgpack/cmp.c
SOURCES_LIB += framework/prometheus/prometheus.c

SOURCES_PRG  = examples/neuropil_hydra.c examples/neuropil_controller.c examples/neuropil_node.c examples/neuropil_sender.c examples/neuropil_cloud.c 
SOURCES_PRG += examples/neuropil_receiver.c examples/neuropil_demo_service.c 
SOURCES_PRG += examples/neuropil_pingpong.c examples/neuropil_raspberry.c examples/web/np_http.c

SOURCES_TST = test/test_suite.c test/test_fuzzing.c

OBJECTS=$(subst src/,build/obj/,$(subst .c,.o,$(SOURCES_LIB)))
PROGRAMS=$(subst examples/,build/obj/,$(subst .c,.o,$(SOURCES_PRG)))
TESTS=$(subst test/,build/obj/,$(subst .c,.o,$(SOURCES_TST)))


all: library test prg

# build/lib/libneuropil.dylib neuropil_hydra neuropil_controller neuropil_node neuropil_sender neuropil_receiver neuropil_receiver_cb neuropil_demo_service neuropil_pingpong neuropil_raspberry

library: build/lib/libneuropil.dylib
test: library neuropil_test_suites test_fuzzing
prg: library neuropil_hydra neuropil_controller neuropil_node neuropil_cloud neuropil_sender neuropil_receiver neuropil_demo_service neuropil_pingpong neuropil_raspberry


neuropil_controller: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_hydra: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_node: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_cloud: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_pingpong: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_demo_service: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_sender: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_raspberry: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_receiver: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) $(NCURSES_LIBRARIES) -Lbuild/lib -lneuropil build/obj/$@.o -o bin/$@

neuropil_test_suites: $(TESTS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(CRITERION_LIBRARIES) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -Lbuild/lib -lneuropil $< -o bin/$@

test_fuzzing: $(TESTS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(CRITERION_LIBRARIES) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fsanitize=fuzzer -Lbuild/lib -lneuropil build/obj/$@.o -o bin/neuropil_$@

build/lib/libneuropil.dylib: $(OBJECTS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(CLANG_SANITIZER) -dynamiclib -std=c99 $(SODIUM_LIBRARIES) $(OBJECTS) -o build/lib/libneuropil.dylib
	# dsymutil build/lib/libneuropil.$(TARGET).dylib -o build/lib/libneuropil.dylib.dSYM

bindings/luajit/build/neuropil_ffi.lua: 
	./bindings/luajit/build.sh

build/obj/%.o: src/%.c
	@mkdir -p $(@D)
	@mkdir -p build/lib
	@mkdir -p bin
	$(CC) -Dx64 -target $(TARGET) $(CFLAGS) -fprofile-instr-generate -fsanitize=fuzzer-no-link $(INCLUDES) $< -o $@

build/obj/%.o: examples/%.c
	@mkdir -p $(@D)
	@mkdir -p build/lib
	@mkdir -p bin
	$(CC) -Dx64 -target $(TARGET) $(CFLAGS) $(INCLUDES) -fprofile-instr-generate -fsanitize=fuzzer-no-link $< -o $@

build/obj/%.o: test/%.c
	@mkdir -p $(@D)
	@mkdir -p build/lib
	@mkdir -p bin
	$(CC) -Dx64 -target $(TARGET) -DDEBUG=1 $(CFLAGS) -fprofile-instr-generate -fsanitize=fuzzer-no-link $(INCLUDES) $< -o $@

clean:
	-rm -r ./bin/* ./build/obj/*.o ./build/lib/*
	-rm -r ./bindings/luajit/neuropil_ffi.lua
	-rm examples/*.o
	-rm ./neuropil_*.log ./test_*.log

clean_log:
	-rm -r *.log
