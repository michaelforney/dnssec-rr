.PHONY: all clean

CFLAGS += -Wall -Wpedantic
LDLIBS = -lbearssl

all: ds dnskey nsec

COMMON_OBJ=\
	base64.o\
	dnssec.o\
	zone.o

libcommon.a: $(COMMON_OBJ)
	$(AR) -rc $@ $(COMMON_OBJ)

ds: ds.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ ds.o libcommon.a $(LDLIBS)

dnskey: dnskey.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ dnskey.o libcommon.a $(LDLIBS)

nsec: nsec.o libcommon.a
	$(CC) $(LDFLAGS) -o $@ nsec.o libcommon.a $(LDLIBS)

ds.o dnskey.o nsec.o rrsig.o $(COMMON_OBJ): dnssec.h

clean:
	rm -f ds ds.o dnskey dnskey.o nsec nsec.o libcommon.a $(COMMON_OBJ)
