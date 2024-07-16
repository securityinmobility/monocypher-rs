CC 		= 	gcc
CFLAGS	= 	-std=c99 -pedantic -Wall -Wextra -O3 -march=native

all: libmonocypher.a 

libmonocypher.a: monocypher.o monocypher-ed25519.o  crypto-aead-ietf.o
	ar cr $@ monocypher.o monocypher-ed25519.o crypto-aead-ietf.o

monocypher.c: Monocypher/src/monocypher.c
	cp $< $@

monocypher.h: Monocypher/src/monocypher.h
	cp $< $@

monocypher-ed25519.c: Monocypher/src/optional/monocypher-ed25519.c
	cp $< $@

monocypher-ed25519.h: Monocypher/src/optional/monocypher-ed25519.h
	cp $< $@

monocypher.o: monocypher.c monocypher.h
	$(CC) $(CFLAGS) -c -o $@ $<

monocypher-ed25519.o: monocypher-ed25519.c \
		monocypher-ed25519.h
	$(CC) $(CFLAGS) -c -o $@ $<

crypto-aead-ietf.o: crypto-aead-ietf.c \
		crypto-aead-ietf.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f libmonocypher.a monocypher.o monocypher-ed25519.o crypto-aead-ietf.o
	rm -f monocypher.c monocypher.h monocypher-ed25519.c  monocypher-ed25519.h

