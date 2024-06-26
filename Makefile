PLATFORM ?= $(shell uname -s)

# CC=clang
# CC=./checker-277/libexec/ccc-analyzer
CC=/usr/local/opt/llvm/bin/clang
# /usr/local/Cellar/llvm/7.0.1/bin/clang

CFLAGS  = -I/usr/local/opt/llvm/include -I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include -fPIC
# CFLAGS=-c -Wall -O3 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
CFLAGS += -c -Wall -Wextra -g -gdwarf-2 -std=c99 -O1 -DDEBUG -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_SYS_EVENT_H -DHAVE_POLL -DHAVE_LINUX_AIO_ABI_H -DEV_USE_FLOOR=1 -DEV_USE_4HEAP=1 -Wno-flag-enum -Wno-nullability-completeness
# CFLAGS+=--analyze -Xanalyzer -analyzer-config -analyzer-checker=alpha.secure -anaylyzer-checker=alpha.core -analyzer-output=html -o build/html
# CFLAGS=-c -Wall -Wextra -pedantic -g -std=c99
# CFLAGS=-c -O3 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL

LDFLAGS=-L/usr/local/opt/llvm/lib -Wl,-rpath,/usr/local/opt/llvm/lib -fPIC

CLANG_SANITIZER=-fno-omit-frame-pointer -fsanitize-address-use-after-scope -fsanitize-coverage=edge,indirect-calls,trace-cmp,trace-div,trace-gep -fcoverage-mapping -fprofile-instr-generate
CLANG_SANITIZER_COMPILE=$(CLANG_SANITIZER) -fsanitize=address,fuzzer-no-link
CLANG_SANITIZER_LINK=$(CLANG_SANITIZER) -fsanitize=address,fuzzer

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
INCLUDES=-I./framework -I./include -I./ext_tools/Criterion/include  -I/usr/include -I/usr/local/opt/llvm/include

SODIUM_LIBRARIES=-L/usr/local/lib -lsodium
CRITERION_LIBRARIES=-L/usr/local/lib -lcriterion
NCURSES_LIBRARIES=-L/usr/local/lib -lncurses

TARGET=x86_64-apple-darwin-macho
# TARGET=x86_64-pc-gnu-elf

SOURCES_LIB  = src/dtime.c src/neuropil.c src/neuropil_data.c src/neuropil_attributes.c src/np_aaatoken.c src/np_axon.c src/util/np_bloom.c src/np_bootstrap.c src/np_crypto.c src/np_dendrit.c
SOURCES_LIB += src/core/np_comp_identity.c src/core/np_comp_msgproperty.c src/core/np_comp_intent.c src/core/np_comp_node.c src/core/np_comp_alias.c
SOURCES_LIB += src/np_dhkey.c src/np_evloop.c src/np_eventqueue.c src/np_glia.c src/np_jobqueue.c src/np_key.c src/np_keycache.c src/np_legacy.c
SOURCES_LIB += src/np_log.c src/np_memory.c src/np_message.c src/np_messagepart.c src/np_network.c src/np_pheromones.c src/util/np_minhash.c
SOURCES_LIB += src/np_node.c src/np_responsecontainer.c src/np_route.c src/util/np_scache.c src/np_serialization.c src/np_shutdown.c src/np_statistics.c
SOURCES_LIB += src/np_threads.c src/np_time.c src/np_token_factory.c src/util/np_tree.c src/util/np_treeval.c src/np_util.c
SOURCES_LIB += src/event/ev.c src/gpio/bcm2835.c  src/json/parson.c src/msgpack/cmp.c src/util/np_statemachine.c

SOURCES_FWLIB = framework/prometheus/prometheus.c framework/http/np_http.c framework/sysinfo/np_sysinfo.c

SOURCES_PRG  = examples/neuropil_hydra.c examples/neuropil_controller.c examples/neuropil_node.c examples/neuropil_sender.c examples/neuropil_cloud.c
SOURCES_PRG += examples/neuropil_receiver.c examples/neuropil_demo_service.c
SOURCES_PRG += examples/neuropil_pingpong.c examples/neuropil_raspberry.c

SOURCES_TST = test/test_suite.c test/test_fuzzing.c

FWOBJECTS=$(subst framework/,build/test/obj/,$(subst .c,.o,$(SOURCES_FWLIB)))
OBJECTS=$(subst src/,build/test/obj/,$(subst .c,.o,$(SOURCES_LIB)))
PROGRAMS=$(subst examples/,build/test/obj/,$(subst .c,.o,$(SOURCES_PRG)))
TESTS=$(subst test/,build/test/obj/,$(subst .c,.o,$(SOURCES_TST)))


all: library test prg

# build/lib/libneuropil.dylib neuropil_hydra neuropil_controller neuropil_node neuropil_sender neuropil_receiver neuropil_receiver_cb neuropil_demo_service neuropil_pingpong neuropil_raspberry

library: build/test/lib/libneuropil.dylib
test: library test_suite test_fuzzing
prg: library neuropil_hydra neuropil_controller neuropil_node neuropil_cloud neuropil_sender neuropil_receiver neuropil_demo_service neuropil_pingpong neuropil_raspberry

neuropil_hydra: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_controller: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_node: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_cloud: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_cloud: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_pingpong: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_demo_service: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_sender: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_raspberry: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

neuropil_receiver: $(PROGRAMS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) $(NCURSES_LIBRARIES) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

test_suite: $(TESTS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(CRITERION_LIBRARIES) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@

test_fuzzing: $(TESTS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER_LINK) -L./build/test/lib -lneuropil ./build/test/obj/$@.o -o ./build/test/bin/$@


build/test/lib/libneuropil.dylib: $(OBJECTS) $(FWOBJECTS)
	$(CC) -g -Dx64 -target $(TARGET) $(LDFLAGS) $(CLANG_SANITIZER_COMPILE) -dynamiclib -std=c99 $(SODIUM_LIBRARIES) $(FWOBJECTS) $(OBJECTS) -o ./build/test/lib/libneuropil.dylib
	# dsymutil build/lib/libneuropil.$(TARGET).dylib -o build/lib/libneuropil.dylib.dSYM

bindings/luajit/build/neuropil_ffi.lua:
	./bindings/luajit/build.sh

build/test/obj/%.o: framework/%.c
	@mkdir -p $(@D)
	@mkdir -p ./build/test/lib
	@mkdir -p bin
	$(CC) -Dx64 -target $(TARGET) $(CFLAGS) $(CLANG_SANITIZER_COMPILE) $(INCLUDES) $< -o $@

build/test/obj/%.o: src/%.c
	@mkdir -p $(@D)
	@mkdir -p ./build/test/lib
	@mkdir -p ./build/test/bin
	$(CC) -Dx64 -target $(TARGET) $(CFLAGS) $(CLANG_SANITIZER_COMPILE) $(INCLUDES) $< -o $@

build/test/obj/%.o: examples/%.c
	@mkdir -p $(@D)
	@mkdir -p ./build/test/lib
	@mkdir -p ./build/test/bin
	$(CC) -Dx64 -target $(TARGET) $(CFLAGS) $(CLANG_SANITIZER_COMPILE) $(INCLUDES) $< -o $@

build/test/obj/%.o: test/%.c
	@mkdir -p $(@D)
	@mkdir -p ./build/test/lib
	@mkdir -p bin
	$(CC) -Dx64 -target $(TARGET) -DDEBUG=1 $(CFLAGS) $(CLANG_SANITIZER_COMPILE) $(INCLUDES) $< -o $@

clean:
	-rm -r ./build/test/bin/* ./build/test/obj/*.o ./build/test/obj/core/*.o ./build/test/lib/*
	-rm -r ./bindings/luajit/neuropil_ffi.lua
	-rm examples/*.o
	-rm ./neuropil_*.log ./test_*.log

clean_log:
	-rm -r *.log
