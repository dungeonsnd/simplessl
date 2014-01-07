CC=g++
CFLAGS=-Wall -g -O0
LIBS=-lcrypto

all: read_write_keys

read_write_keys: read_write_keys.cpp
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)
    
clean:
	@rm -f read_write_keys