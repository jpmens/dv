
CFLAGS=-g -Wall -I/usr/local/include
LIBS=-L/usr/local/lib -lldns

PROG=example

all: $(PROG) 

$(PROG): $(PROG).c dns.o githash.o dns.h dv.o
	$(CC) $(CFLAGS) -o $(PROG) $(PROG).c dns.o githash.o dv.o $(LIBS)
dns.o: dns.c dns.h
	$(CC) $(CFLAGS) -c dns.c 
githash.o: githash.c githash.h
	$(CC) $(CFLAGS) -c githash.c 
dv.o: dv.c dv.h dns.h
	$(CC) $(CFLAGS) -c dv.c

clean:
	rm -rf *.o *.dSYM
