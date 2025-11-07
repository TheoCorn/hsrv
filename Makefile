# CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -g3 -O0
CFLAGS = --pedantic -std=gnu23 -Wall -Wno-pointer-arith -O3 -Wstrict-overflow=5 -fno-strict-aliasing -fanalyzer

COBJ_FLAGS := $(CFLAGS) -fPIC -fvisibility=hidden
# -DTHEOSL_NO_LOG  for no logging

.phony: clean tsrv_so_run all

all: tsrv tsrv_so

tsrv: test.c libhserv.a
	gcc test.c libhserv.a -o tsrv -luring -lssl -lcrypto $(CFLAGS) -flto

tsrv_so: test.c libhserv.so
	gcc test.c -o tsrv_so -L. -luring -lssl -lcrypto -lhserv $(CFLAGS) -flto

libhserv.a: hserv.o file_loading.o default_http_responses.o map.o hsv_params.o http_headers.o mbufcache.o
	ar rcs libhserv.a hserv.o file_loading.o default_http_responses.o map.o hsv_params.o http_headers.o mbufcache.o

libhserv.so: hserv.o file_loading.o default_http_responses.o map.o hsv_params.o http_headers.o mbufcache.o
	gcc -shared -fPIC -flto -fvisibility=hidden -o libhserv.so hserv.o file_loading.o default_http_responses.o map.o hsv_params.o http_headers.o mbufcache.o

hserv.o: _hserv.h hserv.h hserv.c map.h default_http_responses.h
	gcc hserv.c $(COBJ_FLAGS) -c -o hserv.o

file_loading.o: _hserv.h hserv.h file_loading.c
	gcc file_loading.c $(COBJ_FLAGS) -c -o file_loading.o

hsv_params.o: _hserv.h hserv.h params.c
	gcc params.c $(COBJ_FLAGS) -c -o hsv_params.o

default_http_responses.o: default_http_responses.c attributes.h
	gcc default_http_responses.c $(COBJ_FLAGS) -c -o default_http_responses.o

http_headers.o: http_headers.c http_headers.h
	gcc http_headers.c $(COBJ_FLAGS) -c -o http_headers.o

map.o: map.h map.c
	gcc map.c $(COBJ_FLAGS) -c -o map.o

mbufcache.o: mbufcache.c mbufcache.h
	gcc mbufcache.c $(COBJ_FLAGS) -c -o mbufcache.o

clean:
	rm map.o default_http_responses.o file_loading.o hserv.o hsv_params.o http_headers.o mbufcache.o libhserv.a libhserv.so tsrv_so tsrv

tsrv_so_run:
	bash -c 'LD_LIBRARY_PATH="./:$LD_LIBRARY_PATH" ./tsrv_so'
