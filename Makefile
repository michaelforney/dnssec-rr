.PHONY: all clean

CFLAGS += -Wall -Wpedantic
LDLIBS = -lbearssl

all: ds

ds.o dnssec.o: dnssec.h

ds: ds.o dnssec.o
	$(CC) $(LDFLAGS) -o $@ ds.o dnssec.o $(LDLIBS)

clean:
	rm -f ds ds.o dnssec.o
