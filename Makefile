PLATFORM ?= $(shell uname -s)

CC=clang 
# CC=./checker-277/libexec/ccc-analyzer

# CFLAGS=-c -Wall -O3 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
CFLAGS=-c -Wall -Wextra -g -gdwarf-2 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
# CFLAGS+=--analyze -Xanalyzer -analyzer-config -analyzer-checker=alpha.secure -anaylyzer-checker=alpha.core -analyzer-output=html -o build/html
# CFLAGS=-c -Wall -Wextra -pedantic -g -std=c99
# CFLAGS=-c -O3 -std=c99 -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL
LDFLAGS=

# CLANG_SANITIZER=-fsanitize=address -fno-omit-frame-pointer
CLANG_SANITIZER=

ifneq (,$(findstring FreeBSD, $(PLATFORM)))
  override LDFLAGS+=-lutil
else ifneq (,$(findstring Darwin, $(PLATFORM)))
  override CFLAGS+=-Wno-deprecated
  override LDFLAGS+=-framework CoreServices -Wno-deprecated
  override CLANG_SANITIZER+=-mmacosx-version-min=10.11
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


INCLUDES=-I ./include -I ./lib/libsodium-master/src/libsodium/include -I ./lib/criterion-v2.2.1/include
SODIUM_LIBRARIES=-L ./lib/libsodium-master/src/libsodium/.libs -l sodium
CRITERION_LIBRARIES=-L ./lib/criterion-v2.2.1/lib -l criterion

TARGET=x86_64-apple-darwin-macho
# TARGET=x86_64-pc-gnu-elf

SOURCES  = src/dtime.c src/neuropil.c src/np_aaatoken.c src/np_ackentry.c src/np_axon.c src/np_dendrit.c    
SOURCES += src/np_dhkey.c src/np_event.c src/np_glia.c src/np_http.c src/np_jobqueue.c src/np_key.c src/np_keycache.c 
SOURCES += src/np_log.c src/np_memory.c src/np_message.c src/np_messagepart.c src/np_msgproperty.c src/np_network.c
SOURCES += src/np_node.c src/np_pinging.c src/np_route.c src/np_scache.c src/np_serialization.c src/np_statistics.c 
SOURCES += src/np_sysinfo.c src/np_threads.c src/np_time.c src/np_tree.c src/np_treeval.c src/np_util.c 
SOURCES += src/event/ev.c src/gpio/bcm2835.c  src/json/parson.c src/msgpack/cmp.c 

TEST_SOURCES=test/test_suites.c
# test/test_key.c test/neuropil_controller.c test/jrb_test_msg.c test/test_util_uuid.c test/neuropil_hydra.c test/test_list_impl.c test/test_chunk_message.c

OBJECTS=$(SOURCES:.c=.o)
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)

all: src/libneuropil.a ipv6_addrinfo neuropil_hydra neuropil_controller neuropil_node neuropil_sender neuropil_receiver neuropil_receiver_cb neuropil_realmmaster
test: test_suites

# jrb_test_msg test_util_uuid test_key test_list_impl test_chunk_message

neuropil_controller: test/neuropil_controller.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@
# /usr/bin/dsymutil $< -o $@.dsym

neuropil_hydra: test/neuropil_hydra.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@
#/usr/bin/dsymutil $< -o $@.dsym

neuropil_node: test/neuropil_node.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@

neuropil_realmmaster: test/neuropil_realmmaster.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@
# /usr/bin/dsymutil $< -o $@.dsym

# neuropil_realmslave: test/neuropil_realmslave.o
# 	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@
# /usr/bin/dsymutil $< -o $@.dsym

neuropil_sender: test/neuropil_sender.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@

# /usr/bin/dsymutil $< -o $@.dsym
neuropil_receiver: test/neuropil_receiver.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@

# /usr/bin/dsymutil $< -o $@.dsym

neuropil_receiver_cb: test/neuropil_receiver_cb.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate  -L. -lneuropil.$(TARGET) $< -o $@
# /usr/bin/dsymutil $< -o $@.dsym

test_chunk_message: test/test_chunk_message.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CRITERION_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@

test_list_impl: test/test_list_impl.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CRITERION_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@

ipv6_addrinfo: test/ipv6_addrinfo.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CRITERION_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@

test_suites: test/test_suites.o
	-rm test_*.log
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CRITERION_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@

src/libneuropil.a: $(OBJECTS)
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(CLANG_SANITIZER) -dynamiclib -fprofile-instr-generate -std=c99 $(SODIUM_LIBRARIES) $(OBJECTS) -o libneuropil.$(TARGET).a
	dsymutil libneuropil.$(TARGET).a -o libneuropil.$(TARGET).a.dSYM

.c.o: $(SOURCES) $(TEST_SOURCES)
	$(CC) -target $(TARGET) $(CFLAGS) -fprofile-instr-generate $(INCLUDES) $< -o $@

clean:
	-rm -r *.dsym
	-rm ./libneuropil.$(TARGET).a ./src/*.o ./test/*.o ./bin/neuropil_*
	-rm ./neuropil_* ./jrb_test_msg ./test_*
	-rm ./neuropil_*.log ./test_*.log

clean_log:
	-rm -r *.log
