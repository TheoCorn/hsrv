#ifndef HSV_MAXIMUM_REQUEST_SIZE
#define HSV_MAXIMUM_REQUEST_SIZE (1ULL << 13)
#endif

#ifndef HSV_MAXIMUM_REQUEST_NR
// #define HSV_MAXIMUM_REQUEST_NR 1024ULL
#define HSV_MAXIMUM_REQUEST_NR 128ULL
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
#include <liburing.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include "map.h"
#include "http_headers.h"
#include "path_tree.h"
#include "mbufcache.h"
#include "attributes.h"

/// indicates the minimum buffer GID the application may use should be accessed after hsv_init (this is not applicable now but for futre use) 
extern uint64_t hsv_io_uring_buffer_ids_min_free; 

enum hsv_http_request_method : uint_fast8_t {
  HSV_HTTP_METHOD_GET = 0,
  HSV_HTTP_METHOD_HEAD,
  HSV_HTTP_METHOD_POST,
  HSV_HTTP_METHOD_PUT,
  HSV_HTTP_METHOD_DELETE,
  HSV_HTTP_METHOD_CONNECT,
  HSV_HTTP_METHOD_OPTIONS,
  HSV_HTTP_METHOD_TRACE,
  HSV_HTTP_METHOD_PATCH,

  _HSV_HTTP_METHOD_LAST // must be last in the enum
};

extern const char*const hsv_http_request_method_strings[]; // indexed by hsv_http_request_method

enum hsv_handler_type : uint8_t {
  HSV_HANDLER_STATIC_FILE = 0,
  HSV_HANDLER_STATIC_FILE_RAW,
  HSV_HANDLER_REDIRECT,
  HSV_HANDLER_EXTERNAL_HANDLER,
};

struct hsv_file_info {
  int fd;
  __off64_t file_size;
};

struct hsv_static_file_path {
  enum hsv_content_type_id ctype;
  hsv_content_encoding_list_t cencodeing;
  struct hsv_file_info finfo;
};

enum hsv_raw_static_file_path_flags : uint32_t {
  HSV_RAW_STATIC_FILE_PATH_FLAG_NO_HTTP_METHOD_CHECK = 1
};
struct hsv_raw_static_file_path {
  uint32_t flags;
  struct hsv_file_info finfo;
};

struct hsv_redirect_path {
  const char* dest_str;
  const char* code_reason_str;
  uint16_t dest_len;
  uint16_t code_reason_len;
};

struct hsv_external_handler_enviroment {
  int ns_mnt_fd;
  int ns_pid_fd;
  int cgoup;
};

struct hsv_external_handler {
  struct hsv_external_handler_enviroment* enviroment;
  int program_fd;
};

#ifndef HSV_FMAP_H
#define HSV_FMAP_H
MAP_DEF(hsv_static_file_path)
#endif

enum hsv_static_file_block_flags : uint32_t {
  HSV_STATIC_SERVER_BLOCK_FLAG_ALLOW_UNSECURE = (1U), /* allow non TLS connections */
  HSV_STATIC_SERVER_BLOCK_FLAG_AUTHENTICATE = (1U << 1),
  HSV_STATIC_SERVER_BLOCK_FLAG_USE_PATH_TREE = (1U << 2), /* when specified fmap is used inseted of source dir
                                                            this useful if
                                                            1) the global map is large
                                                            2) you wish to serve anonymous files
                                                            3) you do not have an on disk hiarchy */
};

struct hsv_static_file_block {
  union {
  Map(hsv_static_file_path) fmap;
  char* src_dir;
  };
  uint32_t flags;
};

enum hsv_proxy_block_flags : uint32_t {
  HSV_PROXY_BLOCK_FLAG_SECURE_CONNECTION = (1U), /* require TLS for the redirect socket */
  HSV_PROXY_BLOCK_FLAG_AUTHENTICATE = (1U << 1),
  HSV_PROXY_BLOCK_FLAG_IPV6_ADDR = (1U << 2),
};

struct hsv_proxy_block {
  uint32_t flags;
  uint16_t _pad1;
  uint16_t port;
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } ipaddr;
};

#define hsv_redirect_block hsv_redirect_path

struct hsv_path_handler {
  uint32_t flags;
  enum hsv_handler_type htype;
  union {
    struct hsv_static_file_path ss_path_info;  
    struct hsv_raw_static_file_path raw_ss_path_info;  
    struct hsv_redirect_path redirect_path_info;
    struct hsv_external_handler external_hadler_info;
  } info;
};

struct hsv_block_handler {
  enum hsv_handler_type htype;
  union {
    struct hsv_static_file_block sfile;
    struct hsv_proxy_block proxy;
    struct hsv_redirect_block redirect;
  };
};

#ifndef HSV_FD_MAP_H
#define HSV_FD_MAP_H
MAP_DEF(hsv_file_info)
#endif

enum hsv_request_state : uint16_t {
  HSV_REQUEST_STATE_UNINITIALIZED = 0,
  HSV_REQUEST_STATE_SSL_ACCEPT,
  HSV_REQUEST_STATE_CONNECTED,
};

struct _hsv_request_data_ssl_accept {
  SSL *ssl;
  BIO *ssl_bio;
  BIO *net_bio;
};

struct _hsv_request_data_send_file {
  struct hsv_file_info const* file;
  int64_t file_offset; 
  int in_pipe_res;
};

enum _hsv_request_buffer_type {
  _HSV_REQUEST_BUFFER_NONE = 0, 
  _HSV_REQUEST_BUFFER_INPUT_BUFFER_OFFSET,
  _HSV_REQUEST_BUFFER_IOV,
};

struct _hsv_request_buffer {
  enum _hsv_request_buffer_type type;
  union {
    struct iovec iovec;
    uint16_t input_indx;
  } data;
};

struct hsv_request {
  enum hsv_request_state state;
  uint16_t flags;
  int asock_indx; // the index into direct files containing the accepted socket
  union {
    struct _hsv_request_data_ssl_accept ssl_accept;
    struct _hsv_request_data_send_file file_sending;
  } data;

  struct _hsv_request_buffer buffers[HSV_MAXIMUM_REQUEST_SIZE / _HSV_MIN_BUFFER_SIZE+1]; // +1 for HSV_MAXIMUM_REQUEST_SIZE != N * INPUT_URING_INPUT_BUF_SIZE
};

enum _hsv_fixed_file_arr_flags : uint32_t {
  _HSV_FIXED_FILE_ARRAY_FLAG_USE_MEMFD = 1U,
};

struct _hsv_fixed_file_arr {
  int* fd_buf;
  size_t nr_fd;
  size_t max;
  int memfd;
  uint32_t file_size;
  uint32_t flags;
};

enum hsv_params_flags_b0 {
  HSV_PARAMS_IPV4_BIND = 1,
  HSV_PARAMS_IPV6_BIND = 2,
};

#define HSV_PARAMS_PORT_NO_BIND 0U

struct hsv_params {
  uint16_t port; // UNSECURE PORT (HTTP port)
  uint16_t sport; // SECURE PORT (HTTPS port)
  struct in_addr address4;
  struct in6_addr address6;

  uint8_t flags[1];

  struct {
    const char *  cert_path;
    const char* pkey_path;
  } tls;

  struct hsv_path_handler default_handler;

  struct hsv_block_handler* block_handler;
  const char*const * block_paths;
  uint32_t blocks_arr_size;
  uint32_t blocks_nr;

  /*
   maybe replace with the map directly
   though using an array has advantages
   like adding middlewear or other transformations on all paths
  */
  uint32_t paths_nr;
  uint32_t paths_off_cap;
  uint32_t path_handlers_cap;
  struct hsv_path_handler* path_handlers;
  uint32_t* paths_off;

  struct _hsv_fixed_file_arr ffile_arr;

  uint32_t _pbuf_next_off, _pbuf_size, _pbuf_extend_by;
  char* _pbuf;

  struct {
    int pipe_size;
  } static_server;
};

#ifndef HSV_PATH_HANDLER_MAP_H
#define HSV_PATH_HANDLER_MAP_H
MAP_DEF(hsv_path_handler)
#endif

struct hsv_engine_t {
  struct io_uring uring;

  void* buf_ring_backing;

  Map(hsv_path_handler) path_map; /* the first thing that checks for a path (support only exact match) */
  // TODO finish path tree using a trie data structure
  struct hsv_path_tree path_tree; /* if path map does not contain an exact match for the path
                                     the path_tree is checked */

  struct hsv_request requests[HSV_MAXIMUM_REQUEST_NR];
  uint64_t dynuser_data;
  int fixed_file_offset;

  // is zeroed out before each tick
  int input_buffer_buf_offset; 
  // int input_buffer_buf
  struct io_uring_buf_ring* input_buffer_ring;

  struct hsv_path_handler default_handler;

  struct _hsv_mbufcache buf_cache;

  struct {
    SSL_CTX* ctx;
  } tls;
};

// TODO make it return engine and let the result be out param
// because if I change hsv_engine_t it will break existing users
// if it is dynamiclly linked or they use an older header then the static library 
_HSV_PUBLIC_ABI int hsv_init(struct hsv_engine_t* engine, struct hsv_params* params);
_HSV_PUBLIC_ABI int hsv_serve(struct hsv_engine_t* engine);

_HSV_PUBLIC_ABI int hsv_params_init(struct hsv_params* params);
_HSV_PUBLIC_ABI int hsv_params_init_net(struct hsv_params* params, struct in_addr addr4, struct in6_addr addr6, uint16_t port, uint16_t sport);
_HSV_PUBLIC_ABI int hsv_params_init_default_ip(struct hsv_params* params, uint16_t port, uint16_t sport);
_HSV_PUBLIC_ABI int hsv_params_add_path(struct hsv_params* params, const char* const path, struct hsv_path_handler* handler);
_HSV_PUBLIC_ABI int hsv_params_add_block(struct hsv_params* params, const char* const path, struct hsv_block_handler* handler);
_HSV_PUBLIC_ABI void hsv_params_dprint(struct hsv_params* params);

#endif
