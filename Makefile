CFLAGS = --pedantic -std=gnu23 -Wall

.phony: clean

test: hserv.o
	gcc test.c hserv.o -o test -luring $(CFLAGS)

hserv.o: hserv.h hserv.c default_http_responses.h map.h map.o
	gcc hserv.c $(CFLAGS) -c -o hserv.o

map.o: map.h map.c
	gcc map.c $(CFLAGS) -c -o map.o

clean:
	rm test hserv.o map.o
