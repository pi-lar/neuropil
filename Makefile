PLATFORM ?= $(shell uname -s)

CC=clang 
# CC=/Users/schwicht/Downloads/checker-277/libexec/ccc-analyzer

# CFLAGS=-c -Wall -O3 -g -std=c99 
# CFLAGS=-c -Wall -g -gdwarf-2 -std=c99 
# --analyze -Xanalyzer -analyzer-config -analyzer-checker=alpha.secure -anaylyzer-checker=alpha.core -analyzer-output=html -o clang_out
# CFLAGS=-c -Wall -Wextra -pedantic -g -std=c99
CFLAGS=-c -O3 -std=c99
LDFLAGS=

# CLANG_SANITIZER=-fsanitize=address -fno-omit-frame-pointer
CLANG_SANITIZER=

ifneq (,$(findstring FreeBSD, $(PLATFORM)))
  override LDFLAGS+=-lutil
else ifneq (,$(findstring Darwin, $(PLATFORM)))
  override CFLAGS+=-Wno-deprecated
  override LDFLAGS+=-framework CoreServices -Wno-deprecated
#   override CLANG_SANITIZER+=-mmacosx-version-min=10.5
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


INCLUDES=-I ./include -I ./lib/libsodium-master/src/libsodium/include
SODIUM_LIBRARIES=-L ./lib/libsodium-master/src/libsodium/.libs -l sodium

TARGET=x86_64-apple-darwin-macho
# TARGET=x86_64-pc-gnu-elf

SOURCES=src/cmp.c src/dtime.c src/np_jtree.c src/jval.c src/np_aaatoken.c src/np_message.c src/np_memory.c src/np_glia.c src/neuropil.c src/np_jobqueue.c src/np_key.c src/log.c src/np_network.c src/np_node.c src/np_axon.c src/np_container.c src/np_dendrit.c src/np_util.c src/priqueue.c src/np_route.c src/np_msgproperty.c
TEST_SOURCES=test/neuropil_controller.c test/jrb_test_msg.c test/test_dh.c test/neuropil_hydra.c test/test_list_impl.c test/test_chunk_message.c

OBJECTS=$(SOURCES:.c=.o)
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)

all: src/libneuropil.a ipv6_addrinfo neuropil_hydra neuropil_controller neuropil_node neuropil_sender neuropil_receiver neuropil_receiver_cb jrb_test_msg test_dh test_list_impl test_chunk_message

neuropil_controller: test/neuropil_controller.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@

# /usr/bin/dsymutil $< -o $@.dsym

neuropil_hydra: test/neuropil_hydra.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@
#/usr/bin/dsymutil $< -o $@.dsym

neuropil_node: test/neuropil_node.o
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -fprofile-instr-generate -L. -lneuropil.$(TARGET) $< -o $@
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
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@
test_list_impl: test/test_list_impl.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@
ipv6_addrinfo: test/ipv6_addrinfo.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@
jrb_test_msg: test/jrb_test_msg.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@
test_dh: test/test_dh.o
	$(CC) -fprofile-instr-generate $(LDFLAGS) $(SODIUM_LIBRARIES) $(CLANG_SANITIZER) -L. -lneuropil.$(TARGET) $< -o $@

src/libneuropil.a: $(OBJECTS)
	$(CC) -g -target $(TARGET) $(LDFLAGS) $(CLANG_SANITIZER) -dynamiclib -fprofile-instr-generate -std=c99 $(SODIUM_LIBRARIES) $(OBJECTS) -o libneuropil.$(TARGET).a
	cp libneuropil.$(TARGET).a /Users/schwicht/Development/
	dsymutil libneuropil.$(TARGET).a -o /Users/schwicht/Development/libneuropil.$(TARGET).a.dSYM

.c.o: $(SOURCES) $(TEST_SOURCES)
	$(CC) -target $(TARGET) $(CFLAGS) -fprofile-instr-generate $(INCLUDES) $< -o $@

clean:
	-rm -r *.dsym
	-rm ./libneuropil.$(TARGET).a ./src/*.o ./test/*.o ./neuropil_controller ./neuropil_node ./neuropil_sender
	-rm ./neuropil_receiver ./jrb_test_msg ./test_dh
	-rm ./neuropil_*.log ./test_*.log
