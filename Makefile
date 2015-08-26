CC=clang
CFLAGS=-c -Wall -g -std=c99
INCLUDES=-I ./include -I ./lib/libsodium-master/src/libsodium/include
SODIUM_LIBRARIES=-L ./lib/libsodium-master/src/libsodium/.libs -l sodium

SOURCES= src/cmp.c src/dtime.c src/np_jtree.c src/jval.c src/np_aaatoken.c src/np_message.c src/np_memory.c src/np_glia.c src/neuropil.c src/np_jobqueue.c src/np_key.c src/log.c src/np_network.c src/np_node.c src/np_axon.c src/np_container.c src/np_dendrit.c src/np_util.c src/priqueue.c src/np_route.c 
TEST_SOURCES=test/neuropil_controller.c test/jrb_test_msg.c

# TARGET_PLATFORM=-target x86-apple
OBJECTS=$(SOURCES:.c=.o)
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)

all: src/libneuropil.a neuropil_controller neuropil_node neuropil_sender neuropil_receiver neuropil_receiver_cb jrb_test_msg

neuropil_controller: test/neuropil_controller.o
	$(CC) $(SODIUM_LIBRARIES) -L./src -lneuropil $< -o $@

neuropil_node: test/neuropil_node.o
	$(CC) $(SODIUM_LIBRARIES) -L./src -lneuropil $< -o $@
neuropil_sender: test/neuropil_sender.o
	$(CC) $(SODIUM_LIBRARIES) -L./src -lneuropil $< -o $@
neuropil_receiver: test/neuropil_receiver.o
	$(CC) $(SODIUM_LIBRARIES) -L./src -lneuropil $< -o $@
neuropil_receiver_cb: test/neuropil_receiver_cb.o
	$(CC) $(SODIUM_LIBRARIES) -L./src -lneuropil $< -o $@

jrb_test_msg: test/jrb_test_msg.o
	$(CC) $(SODIUM_LIBRARIES) -L./src -lneuropil $< -o $@

src/libneuropil.a: $(OBJECTS)
	$(CC) -dynamiclib -std=c99 $(SODIUM_LIBRARIES) $(OBJECTS) -o $@

.c.o: $(SOURCES) $(TEST_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm ./src/libneuropil.a ./src/*.o ./test/*.o ./neuropil_controller ./neuropil_node ./neuropil_sender
	rm ./neuropil_receiver ./jrb_test_msg
	rm ./neuropil_*.log
