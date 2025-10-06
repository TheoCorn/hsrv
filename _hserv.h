#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef HSERV_PRIV_H
#define HSERV_PRIV_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
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
#include "hserv.h"

#define _HSV_IO_URING_FREE_FIXED_FD_NR 0

#define _HSV_DYN_USER_DATA_MASK (~(((~0ULL) << 60)-1))

#define _HSV_IPV4_ACCEPT_USER_DATA (1ULL << 63)
#define _HSV_IPV6_ACCEPT_USER_DATA ((1ULL << 63) + 1ULL)

#define _HSV_SEND_ERROR_USER_DATA ((1ULL << 62) + 2)
#define _HSV_CLOSE_ERROR_USER_DATA ((1ULL << 62) + 3)

#define _HSV_READ_USER_DATA_BIT (1ULL << 61)

// must be a pow2 number
#define INPUT_URING_INPUT_BUF_NR 1024
#define INPUT_URING_INPUT_BUF_SIZE (1ULL << 13)
#define INPUT_URING_INPUT_BUF_BACKING_SIZE 8388608
#define INPUT_URING_INPUT_BUF_GID 1

#ifdef __x86_64__
// this is equal to 2 * PATH_MAX and is almost guerenteed to be the largest path possible
// a lot of sysclass fail if path is larger PATH_MAX so this is safe for now and will not overflow (I think)
#define HSV_STATIC_PATH_BUFFER_SIZE 8096
#define _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE (1ULL << 21)

#define _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS MAP_HUGETLB | MAP_HUGE_2MB
#define _HSV_SMALL_HUGEMAP_MMAP_FLAGS MAP_HUGETLB | MAP_HUGE_2MB

// packed pages must have start 4 aligned
#define _HSV_FIXED_FILE_ARRAY_PAGE_SIZE (1ULL << 21)

#define _HSV_REQUSET_FLAG_INFLIGHT (1U)

#else
  #error "non x86_64 platforms are not supported because I am lazy"
#endif 

struct linux_dirent64 {
   ino64_t        d_ino;    /* 64-bit inode number */
   off64_t        d_off;    /* Not an offset; see getdents() */
   unsigned short d_reclen; /* Size of this dirent */
   unsigned char  d_type;   /* File type */
   char           d_name[]; /* Filename (null-terminated) */
};

void _hsv_handle_accept(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_read(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);

struct _hsv_fixed_file_arr {
  int* fd_buf;
  size_t nr_fd;
  size_t max;
};
int _hsv_fixed_file_arr_init(struct _hsv_fixed_file_arr *sfiles);
int _hsv_fixed_file_arr_add(struct _hsv_fixed_file_arr *sfiles, int fd);
int _hsv_fixed_file_arr_free(struct _hsv_fixed_file_arr *sfiles);

int _hsv_load_files(struct hsv_params* params, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr *sf);
int _hsv_read_dir(int dir_fd, const char* path, char* path_end, void* db, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf);

// static int _hsv_ss_insert_file(int fd, const char* path, const char* path_end, struct hsv_engine_t* engine, struct _hsv_static_files* sf);
int _hsv_ss_insert_file(int fd, size_t file_size, const char* path, const char* path_end, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf);

inline char* _hsv_add_to_path(const char* path, char* path_end, char* fname) {
  *path_end = '/';
  char* end = strcpy(path_end+1, fname);

  return end;
}

#endif
