CC=gcc
LDFLAGS=-shared -fPIC

# Default target
all: libmaze.so maze libsolver.so

# Generate libmaze.so from libmaze_dummy.o
libmaze.so: libmaze_dummy.c
	$(CC) $(LDFLAGS) -o libmaze.so libmaze_dummy.c

libsolver.so: libsolver.c
	$(CC) $(LDFLAGS) -o libsolver.so libsolver.c

# Link maze.o with libmaze.so to create the executable maze
maze: maze.c libmaze.so
	$(CC) -o maze maze.c -L. -lmaze 

# Clean up
clean:
	rm -f *.so maze

# Tell make that "all" and "clean" are not files
.PHONY: all clean
