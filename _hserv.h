#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef HSERV_PRIV_H
#define HSERV_PRIV_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <error.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <liburing.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/resource.h>

#include <theosl/log.h>

#include "map.h"
#include "default_http_responses.h"
#include "http_headers.h"
#include "hserv.h"

#define _HSV_DEFAULT_HANDLER_FINFO_FD 0

#define _HSV_IO_URING_FREE_FIXED_FD_NR 0

// be cerful what you change here it is a bit of a mess which whould be solved by constexpr or partially by constants instead of macros
#define _HSV_DYN_USER_DATA_MASK (~((~0ULL) << 15))
#define _HSV_DYN_USER_DATA_SHIFT 16
#define OP_USER_DATA(op, req_id) ((op << 16) + req_id)
#define CHANGE_USER_DATA_OP(op, user_data) ((op << 16) + (user_data & (~((~0ULL) << 15))))
#define GET_OP(user_data) (user_data >> 16)
#define GET_DYN_USER_DATA(user_data) (user_data & (~((~0ULL) << 15)))

// high 32 bits of user data for request related operations
enum ops_on_request : uint64_t {
  _HSV_ROP_IPV4_ACCEPT = ((~0ULL) >> _HSV_DYN_USER_DATA_SHIFT),
  _HSV_ROP_IPV6_ACCEPT = (((~0ULL) >> _HSV_DYN_USER_DATA_SHIFT) -1),
  _HSV_ROP_READ = 0,
  _HSV_ROP_INITIAL_SEND,
  _HSV_ROP_SEND_FILE_IN_PIPE,
  _HSV_ROP_SEND_FILE_OUT_PIPE,
  _HSV_ROP_CLOSE_SOCKET,
  _HSV_ROP_SEND_ERROR,
  _HSV_ROP_CLOSE_SOCKET_IMIDIATE,
};

// must be a pow2 number
#define INPUT_URING_INPUT_BUF_NR 1024
#define INPUT_URING_INPUT_BUF_SIZE (1ULL << 13)
#define INPUT_URING_INPUT_BUF_BACKING_SIZE 8388608ULL
#define INPUT_URING_INPUT_BUF_GID 1

#ifdef __x86_64__
// this is equal to 2 * PATH_MAX and is almost guerenteed to be the largest path possible
// a lot of sysclass fail if path is larger PATH_MAX so this is safe for now and will not overflow (I think)
#define HSV_STATIC_PATH_BUFFER_SIZE 8096
#define _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE (1ULL << 21)

#define _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS MAP_HUGETLB | MAP_HUGE_2MB
#define _HSV_SMALL_HUGEMAP_MMAP_FLAGS MAP_HUGETLB | MAP_HUGE_2MB
#define _HSV_SMALL_HUGEMAP_MMAP_SIZE (1ULL << 21)

// packed pages must have start 4 aligned
#define _HSV_FIXED_FILE_ARRAY_PAGE_SIZE (1ULL << 21)

#define _HSV_REQUSET_FLAG_INFLIGHT (1U)

#else
  #error "non x86_64 platforms are not supported because I am lazy"
#endif 

// may be a function is better
#define _HSV_IO_URING_SUBMIT(engine) \
  do { \
    int submit_error = io_uring_submit(&engine->uring); \
    if (submit_error < 0) { \
      LOGE("io_uring_submit %s", strerror(-submit_error)); \
      exit(1); \
    }\
  } while (0)

#define __HSV_IO_URING_SUBMIT(uring) \
  do { \
    int submit_error = io_uring_submit(uring); \
    if (submit_error < 0) { \
      LOGE("io_uring_submit %s", strerror(-submit_error)); \
      exit(1); \
    }\
  } while (0)

#define _HSV_IO_URING_SUBMIT_GO(engine, lable) \
  do { \
    int submit_error = io_uring_submit(&engine->uring); \
    if (submit_error < 0) { \
      LOGE("io_uring_submit %s", strerror(-submit_error)); \
      exit(1); \
    }\
    goto lable; \
  } while (0)


#define hsv_ss_hinfo hsv_static_server_path_info;

typedef uint64_t __attribute((aligned(1))) _hsv_uint64_unaligned;
typedef uint32_t __attribute((aligned(1))) _hsv_uint32_unaligned;

extern inline struct io_uring_sqe* _hsv_io_uring_get_sqe(struct hsv_engine_t* engine);
extern inline struct io_uring_sqe* __hsv_io_uring_get_sqe(struct io_uring* uring); 

struct linux_dirent64 {
   ino64_t        d_ino;    /* 64-bit inode number */
   off64_t        d_off;    /* Not an offset; see getdents() */
   unsigned short d_reclen; /* Size of this dirent */
   unsigned char  d_type;   /* File type */
   char           d_name[]; /* Filename (null-terminated) */
};

void _hsv_handle_accept(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_read(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_socket_close_cqe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_close_socket(struct hsv_engine_t* engine, uint64_t request_index);
void _hsv_handle_send_file_out_pipe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_initial_send(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);

static inline int _hsv_send_file_chunk(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx, __off64_t offset); 

int _hsv_fixed_file_arr_init(struct _hsv_fixed_file_arr *sfiles);
int _hsv_fixed_file_arr_copy(struct _hsv_fixed_file_arr* old, struct _hsv_fixed_file_arr* new);
int _hsv_fixed_file_arr_free_fds(struct _hsv_fixed_file_arr* sfiles);
int _hsv_fixed_file_arr_add(struct _hsv_fixed_file_arr *sfiles, int fd);
int _hsv_fixed_file_arr_free(struct _hsv_fixed_file_arr *sfiles);
int _hsv_fixed_file_arr_reserve(struct _hsv_fixed_file_arr* sfiles, uint32_t min_size);

int _hsv_params_pbuf_init(struct hsv_params* params, size_t initial_size, size_t extend_by);
int64_t _hsv_params_pbuf_add(struct hsv_params* params, const char* const path, size_t path_length);
int _hsv_params_pbuf_free(struct hsv_params* params);
int _hsv_params_path_add(struct hsv_params* const params, const char* const path, const size_t path_length, const struct hsv_path_handler* const handler);

// extern int _hsv_load_files(struct hsv_params* params, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr *sf);
// int _hsv_ss_insert_file(int fd, size_t file_size, const char* path, const char* path_end, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf);

extern 
int _hsv_load_files_in_params(struct hsv_params *params, const char *const root, const char* const mount,
                              struct hsv_block_handler *handler); 

static inline void _hsv_free_request_buffers(struct hsv_engine_t* engine, struct hsv_request* request);

static inline void _hsv_ibufring_return(struct hsv_engine_t* engine, char* buffer, uint16_t buf_id);

static inline struct io_uring_sqe* _hsv_enqueue_read(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx);


struct _hsv_dents_buffers {
  void** buffers;
  size_t len;
  size_t cap;
};

int _hsv_read_dir(int dir_fd, const char* path, char* path_end, struct _hsv_dents_buffers* dbs, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf);

int _hsv_dents_buffers_init(struct _hsv_dents_buffers* db);
void* _hsv_dents_get(struct _hsv_dents_buffers* db);
// frees the last used buffer
void _hsv_dents_free_buffer(struct _hsv_dents_buffers* db);
void _hsv_dents_free_buffers(struct _hsv_dents_buffers* db);

#define _HSV_SS_KEY_BUFFER_INITIAL_SIZE (1 << 21)
#define _HSV_SS_KEY_BUFFER_INITIAL_MMAP_HPAGE_FLAGS MAP_HUGETLB | MAP_HUGE_2MB
int _hsv_ss_key_buffer_init(struct hsv_engine_t* engine);
int _hsv_ss_key_buffer_free(struct hsv_engine_t* engine);

int _hsv_read_dir_should_ingnore_file(char* dname);

#endif
