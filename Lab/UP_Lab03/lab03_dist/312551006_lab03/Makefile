CC=gcc
LDFLAGS=-shared -fPIC

# Default target
all: libsolver.so

libsolver.so: libsolver.c
	$(CC) $(LDFLAGS) -o libsolver.so libsolver.c

# Clean up
clean:
	rm -f *.so

# Tell make that "all" and "clean" are not files
.PHONY: all clean
