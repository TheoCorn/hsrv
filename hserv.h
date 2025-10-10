#ifndef HSV_MAXIMUM_REQUEST_SIZE
#define HSV_MAXIMUM_REQUEST_SIZE (1ULL << 13)
#endif

#ifndef HSV_MAXIMUM_REQUEST_NR
#define HSV_MAXIMUM_REQUEST_NR 1024ULL
#endif

#ifndef HSV_NET_BACKLOG
#define HSV_NET_BACKLOG 16
#endif

#ifndef HSV_IO_URING_FREE_FIXED_FD_NR 
#define HSV_IO_URING_FREE_FIXED_FD_NR 0ULL
#endif

// this allows user to register his own static file offsets
// and is to be used in combination with HSV_IO_URING_FREE_FIXED_FD_NR
#ifndef HSV_IO_URING_DYN_ENTERIES_OFFSET
#define HSV_IO_URING_DYN_ENTERIES_OFFSET 0ULL
#endif

#ifndef HSV_IO_URING_ENTERIES_NR
#define HSV_IO_URING_ENTERIES_NR 4096ULL
#endif

// This has to be set to the size of the smallest input buffer to ensure a buffer overflow does not happen
// as there is currently on one buffer size it is set to HSV_INPUT_BUF_SIZE which is the default buffer for incomming request
// and will probably remain the smallest buffer
#define _HSV_MIN_BUFFER_SIZE (1ULL << 13)

#ifndef HSERV_H
#define HSERV_H

#include <stdint.h>
#include <unistd.h>
#include "map.h"
#include <liburing.h>
#include <netinet/in.h>

/// indicates the minimum buffer GID the application may use should be accessed after hsv_init (this is not applicable now but for futre use) 
extern uint64_t hsv_io_uring_buffer_ids_min_free; 

struct file_info {
  int fd;
  __off64_t file_size;
};

#ifndef HSV_FD_MAP_H
#define HSV_FD_MAP_H
MAP_DEF(file_info)
#endif

// indicates the end of hsv_request.buffers
#define HSV_REQUEST_BUFFER_ARRAY_ENDING (-1)

struct hsv_request {
  uint32_t flags;
  int asock_indx; // the index into direct files containing the accepted socket
  size_t current_size;
  struct {
    struct file_info* file;
    int64_t file_offset; 
  } file_sending;
  int buffers[HSV_MAXIMUM_REQUEST_SIZE / _HSV_MIN_BUFFER_SIZE+1]; // +1 for HSV_MAXIMUM_REQUEST_SIZE != N * INPUT_URING_INPUT_BUF_SIZE
};

struct hsv_params {
  uint16_t port;
  struct in_addr address4;
  struct in6_addr address6;
  struct {
  char** dirs;
  unsigned nr_dirs;
  int pipe_size;
  } static_server;
};

struct hsv_engine_t {
  struct io_uring uring;
  struct {
    Map(file_info) fd_map;
    // char** roots;
    // uint32_t nr_roots;

    char* key_buf;
    size_t key_buf_size;
    char* key_buf_next;

    void* buf_ring_backing;
  } static_server;

  struct hsv_request requests[HSV_MAXIMUM_REQUEST_NR];
  uint64_t dynuser_data;
  int fixed_file_offset;

  // is zeroed out before each tick
  int input_buffer_buf_offset; 
  // int input_buffer_buf
  struct io_uring_buf_ring* input_buffer_ring;
};

// TODO make it return engine and let the result be out param
// because if I change hsv_engine_t it will break existing users
// if it is dynamiclly linked or they use an older header then the static library 
int hsv_init(struct hsv_engine_t* engine, struct hsv_params* params);
int hsv_serve(struct hsv_engine_t* engine);

#endif
