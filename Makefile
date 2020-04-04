.PHONY: all clean

CFLAGS += -Wall -Wpedantic
LDLIBS = -lbearssl

all: dsfromkey

dsfromkey.o dnssec.o: dnssec.h

dsfromkey: dsfromkey.o dnssec.o
	$(CC) $(LDFLAGS) -o $@ dsfromkey.o dnssec.o $(LDLIBS)

clean:
	rm -f dsfromkey dsfromkey.o dnssec.o
