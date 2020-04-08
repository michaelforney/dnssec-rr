.PHONY: all clean

CFLAGS += -Wall -Wpedantic
LDLIBS = -lbearssl

all: ds dnskey

ds.o dnskey.o dnssec.o: dnssec.h

ds: ds.o dnssec.o
	$(CC) $(LDFLAGS) -o $@ ds.o dnssec.o $(LDLIBS)

dnskey: dnskey.o dnssec.o
	$(CC) $(LDFLAGS) -o $@ dnskey.o dnssec.o $(LDLIBS)

clean:
	rm -f ds ds.o dnskey dnskey.o dnssec.o
