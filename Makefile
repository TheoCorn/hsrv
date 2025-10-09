CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -g3 -O0

.phony: clean

tsrv: hserv.o map.o test.c
	gcc test.c hserv.o map.o -o tsrv -luring $(CFLAGS)

hserv.o: _hserv.h hserv.h hserv.c default_http_responses.h map.h map.o
	gcc hserv.c $(CFLAGS) -c -o hserv.o

map.o: map.h map.c
	gcc map.c $(CFLAGS) -c -o map.o

clean:
	rm tsrv hserv.o map.o
