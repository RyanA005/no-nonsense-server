CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS += -Icommon -D_GNU_SOURCE
LDLIBS += -lcrypto

spooky-client: client/main.o common/protocol.o common/crypto.o
	$(CC) $(CFLAGS) -o $@ client/main.o common/protocol.o common/crypto.o $(LDLIBS)

clean:
	rm -f spooky-client client/main.o common/protocol.o common/crypto.o
