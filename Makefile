.PHONY: all clean

CFLAGS += -Wall -Wpedantic
LDLIBS = -lbearssl

all: ds dnskey nsec rrsig tlsa

COMMON_OBJ=\
	base16.o\
	base64.o\
	dnssec.o\
	key.o\
	zone.o

libcommon.a: $(COMMON_OBJ)
	$(AR) -rc $@ $(COMMON_OBJ)

ds: ds.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ ds.o libcommon.a $(LDLIBS)

dnskey: dnskey.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ dnskey.o libcommon.a $(LDLIBS)

nsec: nsec.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ nsec.o libcommon.a $(LDLIBS)

rrsig: rrsig.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ rrsig.o libcommon.a $(LDLIBS)

tlsa: tlsa.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ tlsa.o libcommon.a $(LDLIBS)

ds.o dnskey.o nsec.o rrsig.o $(COMMON_OBJ): dnssec.h

clean:
	rm -f ds ds.o dnskey dnskey.o nsec nsec.o rrsig rrsig.o tlsa tlsa.o libcommon.a $(COMMON_OBJ)
