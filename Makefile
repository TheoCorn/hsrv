# CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -g3 -O0
CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -O3
# -DTHEOSL_NO_LOG  for no logging

.phony: clean

tsrv: test.c libhserv.a
	gcc test.c libhserv.a -o tsrv -luring $(CFLAGS)

libhserv.a: hserv.o file_loading.o default_http_responses.o map.o
	ar rcs libhserv.a hserv.o file_loading.o default_http_responses.o map.o 

hserv.o: _hserv.h hserv.h hserv.c map.h default_http_responses.h
	gcc hserv.c $(CFLAGS) -c -o hserv.o

file_loading.o: _hserv.h hserv.h file_loading.c
	gcc file_loading.c $(CFLAGS) -c -o file_loading.o

default_http_responses.o: default_http_responses.c attributes.h
	gcc default_http_responses.c $(CFLAGS) -c -o default_http_responses.o

map.o: map.h map.c
	gcc map.c $(CFLAGS) -c -o map.o

clean:
	rm map.o default_http_responses.o file_loading.o hserv.o libhserv.a tsrv
