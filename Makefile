
CFLAGS=-g -Wall -I/usr/local/include
LIBS=-L/usr/local/lib -lldns

PROG=example

all: $(PROG) 

$(PROG): $(PROG).c dns.o githash.o dns.h sha1.o dv.o
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).c dns.o githash.o sha1.o dv.o $(LIBS)
dns.o: dns.c dns.h
	$(CC) $(CFLAGS) -c dns.c 
githash.o: githash.c githash.h sha1.h
	$(CC) $(CFLAGS) -c githash.c 
sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c sha1.c
dv.o: dv.c dv.h dns.h
	$(CC) $(CFLAGS) -c dv.c

clean:
	rm -rf *.o *.dSYM
