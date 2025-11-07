# CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -g3 -O0
CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -O3 -Wstrict-overflow=5 -fno-strict-aliasing -fanalyzer
# -DTHEOSL_NO_LOG  for no logging

.phony: clean

tsrv: test.c libhserv.a
	gcc test.c libhserv.a -o tsrv -luring -lssl -lcrypto $(CFLAGS) -flto

libhserv.a: hserv.o file_loading.o default_http_responses.o map.o hsv_params.o http_headers.o mbufcache.o
	ar rcs libhserv.a hserv.o file_loading.o default_http_responses.o map.o hsv_params.o http_headers.o mbufcache.o

hserv.o: _hserv.h hserv.h hserv.c map.h default_http_responses.h
	gcc hserv.c $(CFLAGS) -c -o hserv.o

file_loading.o: _hserv.h hserv.h file_loading.c
	gcc file_loading.c $(CFLAGS) -c -o file_loading.o

hsv_params.o: _hserv.h hserv.h params.c
	gcc params.c $(CFLAGS) -c -o hsv_params.o

default_http_responses.o: default_http_responses.c attributes.h
	gcc default_http_responses.c $(CFLAGS) -c -o default_http_responses.o

http_headers.o: http_headers.c http_headers.h
	gcc http_headers.c $(CFLAGS) -c -o http_headers.o

map.o: map.h map.c
	gcc map.c $(CFLAGS) -c -o map.o

mbufcache.o: mbufcache.c mbufcache.h
	gcc mbufcache.c $(CFLAGS) -c -o mbufcache.o

clean:
	rm map.o default_http_responses.o file_loading.o hserv.o hsv_params.o http_headers.o mbufcache.o libhserv.a tsrv
