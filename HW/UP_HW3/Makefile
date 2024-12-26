CC=gcc

all: sdb libcapstone.a

sdb: sdb.c 
	$(CC) -o sdb sdb.c ./libcapstone.a

clean:
	rm sdb

.PHONY: all clean
