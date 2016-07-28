SRC=src/snidump.c src/tls.c src/http.c src/aux.c

.PHONY: all debug clean

all: bin/snidump bin/snidump_noether

debug: bin/snidump_dbg bin/snidump_noether_dbg

bin/snidump: src/*
	mkdir -p bin && \
	gcc -D__DEBUG__=0 -Wall \
		$(SRC) \
		-lpcap -lpcre \
		-o bin/snidump

bin/snidump_dbg: src/*
	mkdir -p bin && \
	gcc -D__DEBUG__=1 -Wall -ggdb \
		$(SRC) \
		-lpcap -lpcre \
		-o bin/snidump_dbg

bin/snidump_noether: src/*
	mkdir -p bin && \
	gcc -D__DEBUG__=0 -Wall \
		-D__NO_ETHERNET__ \
		$(SRC) \
		-lpcap -lpcre \
		-o bin/snidump_noether

bin/snidump_noether_dbg: src/*
	mkdir -p bin && \
	gcc -D__DEBUG__=1 -Wall -ggdb \
		-D__NO_ETHERNET__ \
		$(SRC) \
		-lpcap -lpcre \
		-o bin/snidump_noether_dbg

clean:
	rm -rf bin
