PLATFORM ?= $(shell uname -s)

CC=clang
CFLAGS=-c -Wall -g -std=c99
# CFLAGS=-c -Wall -Wextra -pedantic -g -std=c99
# CFLAGS=-c -O3 -std=c99
LDFLAGS=

ifneq (,$(findstring FreeBSD, $(PLATFORM)))
  override LDFLAGS+=-lutil
else ifneq (,$(findstring Darwin, $(PLATFORM)))
  override CFLAGS+=-Wno-deprecated
  override LDFLAGS+=-framework CoreServices -Wno-deprecated
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

SOURCES=src/cmp.c src/dtime.c src/np_jtree.c src/jval.c src/np_aaatoken.c src/np_message.c src/np_memory.c src/np_glia.c src/neuropil.c src/np_jobqueue.c src/np_key.c src/log.c src/np_network.c src/np_node.c src/np_axon.c src/np_container.c src/np_dendrit.c src/np_util.c src/priqueue.c src/np_route.c 
TEST_SOURCES=test/neuropil_controller.c test/jrb_test_msg.c test/test_dh.c

OBJECTS=$(SOURCES:.c=.o)
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)

all: src/libneuropil.a ipv6_addrinfo neuropil_controller neuropil_node neuropil_sender neuropil_receiver neuropil_receiver_cb jrb_test_msg test_dh

neuropil_controller: test/neuropil_controller.o
	$(CC) -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@

neuropil_node: test/neuropil_node.o
	$(CC) -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@
neuropil_sender: test/neuropil_sender.o
	$(CC) -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@
neuropil_receiver: test/neuropil_receiver.o
	$(CC) -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@
neuropil_receiver_cb: test/neuropil_receiver_cb.o
	$(CC) -target $(TARGET) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@

ipv6_addrinfo: test/ipv6_addrinfo.o
	$(CC) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@
jrb_test_msg: test/jrb_test_msg.o
	$(CC) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@
test_dh: test/test_dh.o
	$(CC) $(LDFLAGS) $(SODIUM_LIBRARIES) -L. -lneuropil.$(TARGET) $< -o $@

src/libneuropil.a: $(OBJECTS)
	$(CC) -target $(TARGET) $(LDFLAGS) -dynamiclib -std=c99 $(SODIUM_LIBRARIES) $(OBJECTS) -o libneuropil.$(TARGET).a

.c.o: $(SOURCES) $(TEST_SOURCES)
	$(CC) -target $(TARGET) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	-rm ./libneuropil.$(TARGET).a ./src/*.o ./test/*.o ./neuropil_controller ./neuropil_node ./neuropil_sender
	-rm ./neuropil_receiver ./jrb_test_msg ./test_dh
	-rm ./neuropil_*.log ./test_*.log
