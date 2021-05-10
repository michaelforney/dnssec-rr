.PHONY: all install clean

-include config.mk

PREFIX?=/usr/local
BINDIR?=$(PREFIX)/bin
MANDIR?=$(PREFIX)/share/man
CFLAGS+=-Wall -Wpedantic
LDLIBS?=-lbearssl

COMMON_OBJ=\
	base16.o\
	base64.o\
	dnssec.o\
	key.o\
	zone.o
TOOLS=dnskey ds nsec rrsig tlsa

all: $(TOOLS)

libcommon.a: $(COMMON_OBJ)
	$(AR) -rc $@ $(COMMON_OBJ)

dnskey: dnskey.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ dnskey.o libcommon.a $(LDLIBS)

ds: ds.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ ds.o libcommon.a $(LDLIBS)

nsec: nsec.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ nsec.o libcommon.a $(LDLIBS)

rrsig: rrsig.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ rrsig.o libcommon.a $(LDLIBS)

tlsa: tlsa.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ tlsa.o libcommon.a $(LDLIBS)

dnskey.o ds.o nsec.o rrsig.o $(COMMON_OBJ): dnssec.h

install: $(TOOLS)
	mkdir -p $(DESTDIR)$(BINDIR)
	cp $(TOOLS) $(DESTDIR)$(BINDIR)/
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp $(TOOLS:%=%.1) $(DESTDIR)$(MANDIR)/man1/

clean:
	rm -f $(TOOLS) $(TOOLS:%=%.o) libcommon.a $(COMMON_OBJ)
