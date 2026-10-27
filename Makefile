CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CPPFLAGS += -Icommon -D_GNU_SOURCE
LDLIBS += -lcrypto

PYTHON := .venv/bin/python
VENV_STAMP := .venv/.installed
SERVER_OBJS = server/main.o server/network.o server/auth.o server/shell.o \
	server/filesystem.o server/users.o common/protocol.o common/crypto.o
CLIENT_OBJS = client/main.o common/protocol.o common/crypto.o

.PHONY: all server client test generate generate-prod clean participant-dist venv

all: server client

server: spooky-server

client: spooky-client

spooky-server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $(SERVER_OBJS) $(LDLIBS)

spooky-client: $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $(CLIENT_OBJS) $(LDLIBS)

venv: $(VENV_STAMP)

$(VENV_STAMP): tools/requirements.txt
	python3 -m venv .venv
	$(PYTHON) -m pip install -r tools/requirements.txt
	touch $(VENV_STAMP)

generate: $(VENV_STAMP)
	$(PYTHON) tools/generate_challenge.py --out data --flag 'spooky{reused_k_no_nons3nse_89f3ae32316e}' --seed 20261013

generate-prod: $(VENV_STAMP)
	$(PYTHON) tools/generate_challenge.py --out data --flag 'spooky{reused_k_no_nons3nse_89f3ae32316e}'

test: spooky-server spooky-client generate
	$(PYTHON) -m unittest discover -s tests -v

participant-dist: spooky-client generate
	rm -rf dist/participant
	mkdir -p dist/participant/client dist/participant/common dist/participant/docs dist/participant/data
	cp client/main.c dist/participant/client/main.c
	cp common/protocol.c common/protocol.h common/crypto.c common/crypto.h dist/participant/common/
	cp docs/PARTICIPANT.md dist/participant/README.md
	cp docs/PARTICIPANT.md docs/PROTOCOL.md dist/participant/docs/
	cp data/public/general.pem dist/participant/data/general.pem
	cp data/public/README.txt dist/participant/data/README.txt
	cp deploy/Makefile.participant dist/participant/Makefile

clean:
	rm -f spooky-server spooky-client $(SERVER_OBJS) $(CLIENT_OBJS)

$(SERVER_OBJS) $(CLIENT_OBJS): common/protocol.h common/crypto.h
