CC = gcc
LDFLAG = -fPIC -shared

all: lib.so logger

lib.so: lib.c 
	$(CC) $(LDFLAG) -o lib.so lib.c

logger: logger.c 
	$(CC) -o logger logger.c

.PHONY: clean

clean:
	rm logger lib.so *.log ooo.txt file.txt