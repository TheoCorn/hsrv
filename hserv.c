#include "_hserv.h"

// it doesn't much matter but in the futre I might want to use the weak attribute to not have these #ifndef…
#ifndef MAP_FILE_INFO_IMPL
#define MAP_FILE_INFO_IMPL
MAP_IMPL(file_info)
#endif

// this is set much higher then needed but that is OK
uint64_t hsv_io_uring_buffer_ids_min_free = 33; 

int hsv_init(struct hsv_engine_t* engine, struct hsv_params* params) {

  int ipv4sock = socket(AF_INET, SOCK_STREAM, 0);
  int opt = 1;
  setsockopt(ipv4sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  int ipv6sock = socket(AF_INET6, SOCK_STREAM, 0);
  setsockopt(ipv6sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(ipv6sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
  

  // TODO update goto lables to close sockets …, switch from return to goto dealloc handler

  {
    struct sockaddr_in ipv4_addr;
    ipv4_addr.sin_family = AF_INET;
    ipv4_addr.sin_addr = params->address4;
    ipv4_addr.sin_port = htons(params->port);

    if (bind(ipv4sock, &ipv4_addr, sizeof(struct sockaddr_in))) {
      LOGE("failed to bind ipv4 socket %s", strerror(errno));
      return 1;
    }

    struct sockaddr_in6 ipv6_addr;
    ipv6_addr.sin6_family = AF_INET6;
    ipv6_addr.sin6_addr = params->address6;
    ipv6_addr.sin6_port = ipv4_addr.sin_port;
    
    if (bind(ipv6sock, &ipv6_addr, sizeof(ipv6_addr))) {
      LOGE("failed to bind ipv6 socket %s", strerror(errno));
      return 1;
    }

    if (listen(ipv6sock, HSV_NET_BACKLOG)) {
      LOGE("failed to listen on IPv6 sock %s", strerror(errno));
      return 1;
    }
    if (listen(ipv4sock, HSV_NET_BACKLOG)) {
      LOGE("failed to listen on IPv4 sock %s", strerror(errno));
      return 1;
    }
  }
  
  int ret = UINT8_MAX;
  if (mapfile_info_init(&engine->static_server.fd_map, 4096)) {
    return -1;
  }

  struct _hsv_fixed_file_arr sf;
  
  if (_hsv_fixed_file_arr_init(&sf)) {
    // TODO I forgot to create a map free function when it's aviable put it here
    ret = -2;
    goto dealloc_static_files_err;
  }
  if (_hsv_load_files(params, engine, &sf)) {
    _hsv_fixed_file_arr_free(&sf);
    // TODO I forgot to create a map free function when it's aviable put it here
    ret = 1;
    goto dealloc_load_files_err;
  }

  LOGD("file descriptors of files (nr: %zu)", sf.nr_fd);
  for (size_t i = 0; i < sf.nr_fd; ++i) {
    printf("%d\t", sf.fd_buf[i]);
  }
  putchar('\n');
  
  // each request has a pipe to do zero copy file send hence 3 * MAX_REQUESTS_NR (1 socket, 1 pipe input, 1 pipe output)
  size_t min_ff_buf_size = sf.nr_fd + (3 * HSV_MAXIMUM_REQUEST_NR) + HSV_IO_URING_FREE_FIXED_FD_NR + HSV_IO_URING_ENTERIES_NR;
  size_t ff_buf_dyn_start = sf.nr_fd + (2 * HSV_MAXIMUM_REQUEST_NR) + HSV_IO_URING_DYN_ENTERIES_OFFSET;
  if (sf.max - sf.nr_fd < min_ff_buf_size) {
    size_t new_len = min_ff_buf_size;
    new_len = (new_len + _HSV_FIXED_FILE_ARRAY_PAGE_SIZE-1) & ~(_HSV_FIXED_FILE_ARRAY_PAGE_SIZE-1);
    void* new_addr = mremap(sf.fd_buf, sf.max * sizeof(int), new_len, MREMAP_MAYMOVE);
    if (MAP_FAILED == new_addr) {
      // it is late I am not adding the dealloc :(
      return 1;
    }

    sf.fd_buf = (int*) new_addr;
    sf.max = new_len / sizeof(int);
  }

  size_t mstatic_end = sf.nr_fd + (2 * HSV_MAXIMUM_REQUEST_NR);
  for (size_t i = sf.nr_fd; i < mstatic_end; i += 2) {
    retry_pipe:
    if (pipe2(sf.fd_buf + i, 0)) {
      LOGW("failed to create a pipe ff_indx: %zu %s", i, strerror(errno));
      
      struct rlimit64 flimit;
      if (getrlimit64(RLIMIT_NOFILE, &flimit)) {
        LOGE("failed to get FD limit: %s", strerror(errno));
        exit(1);
      }
      if (flimit.rlim_cur == flimit.rlim_max) {
        LOGE("failed to increse FD limit to create the pipe max is %zu", flimit.rlim_max);
        exit(1);
      }

      flimit.rlim_cur = flimit.rlim_max;
      if (setrlimit64(RLIMIT_NOFILE, &flimit)) {
        LOGE("failed to set FD limit %s", strerror(errno));
        exit(1);
      }
      LOGI("incresed the FD limit to %zu", flimit.rlim_cur);
      goto retry_pipe;
    }
  }

  for (size_t i = mstatic_end; i < sf.max; ++i) {
    sf.fd_buf[i] = -1;
  }

  unsigned int flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32 | IORING_SETUP_R_DISABLED | IORING_SETUP_SQE128 | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY | IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER;
  struct io_uring* uring = &engine->uring;
  ret = io_uring_queue_init(HSV_IO_URING_ENTERIES_NR, uring, flags);
  if (ret) goto dealloc_ring_init_err;


  ret = io_uring_register(uring->ring_fd, IORING_REGISTER_FILES, sf.fd_buf, sf.max);
  if (ret) goto dealloc_w_ring;

  if (io_uring_register_file_alloc_range(uring, ff_buf_dyn_start, sf.max - ff_buf_dyn_start)) {
    LOGE("iouring register file alloc range failed %s", strerror(errno));
    ret = 1;
    goto dealloc_w_ring;
  }

  struct io_uring_buf_ring *ibufring = io_uring_setup_buf_ring(uring, INPUT_URING_INPUT_BUF_NR, INPUT_URING_INPUT_BUF_GID, IOU_PBUF_RING_INC, &ret);
  if (ret) {
    LOGE("iouring pbuf ring register error %d %s", ret, strerror(errno));
    goto dealloc_w_ring;
  }

  void* buf_ring_backing = mmap(NULL, INPUT_URING_INPUT_BUF_BACKING_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_SMALL_HUGEMAP_MMAP_FLAGS, -1, 0);
  engine->static_server.buf_ring_backing = buf_ring_backing;
  for (uint16_t i = 0; i < INPUT_URING_INPUT_BUF_NR; ++i) {
    struct io_uring_buf* urb = ibufring->bufs + i;
    *urb = (struct io_uring_buf) {.bid = i, .addr = (__u64)(buf_ring_backing + i * INPUT_URING_INPUT_BUF_SIZE), .len = INPUT_URING_INPUT_BUF_SIZE};
  }
  io_uring_buf_ring_advance(ibufring, INPUT_URING_INPUT_BUF_NR);

  struct io_uring_sqe* accept4_sqe = io_uring_get_sqe(uring);
  io_uring_prep_multishot_accept_direct(accept4_sqe, ipv4sock, NULL, 0, 0);
  accept4_sqe->user_data = _HSV_IPV4_ACCEPT_USER_DATA;
  accept4_sqe->file_index = IORING_FILE_INDEX_ALLOC;

  struct io_uring_sqe* accept6_sqe = io_uring_get_sqe(uring);
  io_uring_prep_multishot_accept_direct(accept6_sqe, ipv6sock, NULL, 0, 0);
  accept4_sqe->user_data = _HSV_IPV6_ACCEPT_USER_DATA;
  accept4_sqe->file_index = IORING_FILE_INDEX_ALLOC;

  if (io_uring_enable_rings(uring)) {
    LOGE("Failed to enable rings", NULL);
    exit(1);
  }

  if (2 != io_uring_submit(uring)) {
    LOGE("two sockets should have SQEs", NULL);
    exit(1);
  }

  _hsv_fixed_file_arr_free(&sf);
  return 0;


  dealloc_all:
  dealloc_w_ring:
  dealloc_ring_init_err:
  dealloc_load_files_err:
  _hsv_fixed_file_arr_free(&sf);
  dealloc_static_files_err:
  // TODO dealloc map
  return ret;
}

int hsv_serve(struct hsv_engine_t* engine) {
  while (true) {
    struct io_uring_cqe* cqe;
    int e = io_uring_wait_cqe(&engine->uring, &cqe);
    if (e) {
      return -1;
    }

    unsigned head;
    unsigned nr = 0U;
    io_uring_for_each_cqe(&engine->uring, head, cqe) {

      if (!(cqe->user_data & ~_HSV_DYN_USER_DATA_MASK)) {
        if (_HSV_READ_USER_DATA_BIT & cqe->user_data) {
          _hsv_handle_read(engine, cqe);
        } else {
          _hsv_handle_accept(engine, cqe);
        }
      } else {
        switch (cqe->user_data) {
          case _HSV_IPV6_ACCEPT_USER_DATA:
            LOGD("ACCEPTED A IPV6 socket", NULL);
          case _HSV_IPV4_ACCEPT_USER_DATA:
            _hsv_handle_accept(engine, cqe);
          break;
          case _HSV_SEND_ERROR_USER_DATA:
            LOGW("error sending error message", NULL);
          break;
          case _HSV_CLOSE_ERROR_USER_DATA:
            LOGW("error closing fixed fd", NULL);
          break;

          default:
         
          break;
        }
      }

      nr++;
    }  
    io_uring_cq_advance(&engine->uring, nr);
  }
}

static int _hsv_deal_with_file(int fd, const char* path, char* path_end, void* dents_buffer, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf) {
   struct stat64 fs;
  if (fstat64(fd, &fs)) {
   return 1; 
  }

  int e;
  switch (fs.st_mode & S_IFMT) {
    case __S_IFDIR:
      e = _hsv_read_dir(fd, path, path_end, dents_buffer, engine, sf);
      break;
    case __S_IFREG: {
        e = _hsv_ss_insert_file(fd, fs.st_size, path, path_end, engine, sf);
      }
      break;
    default:
      LOGW("invalid file type in deal with file (inode: %zu)", fs.st_ino);
      return 2;
      break;
  } 

  return e;
}

int _hsv_load_files(struct hsv_params* params, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr *sf) {

  void* dents_buffer = mmap(NULL, _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS, -1, 0);
  if (dents_buffer == MAP_FAILED) {
    LOGE("it is very likely a mmap failed because you have not enabled hugepages: %s", strerror(errno));
    return 1;
  }

  char* path_buf = mmap(NULL, HSV_STATIC_PATH_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  for (size_t i = 0; i < params->static_server.nr_dirs; ++i) {
    char* end = strcpy(path_buf, params->static_server.dirs[i]);
    int fd = open(path_buf, O_RDONLY);
    int e;
    if ((e = _hsv_deal_with_file(fd, path_buf, end, dents_buffer, engine, sf))) {
      LOGE("problem with %s (%d)", path_buf, e);
    }
  }

  // TODO check for errors on unmaps
  munmap(path_buf, HSV_STATIC_PATH_BUFFER_SIZE);
  munmap(dents_buffer, _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE);

  return 0;
}


int _hsv_read_dir(int dir_fd, const char* path, char* path_end, void* db, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf) {
  ssize_t dlen;
  while ((dlen = getdents64(dir_fd, db, _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE))) {
    if (dlen == -1) {
      LOGE("error getdents64 %s", strerror(errno));
      return -2;
    }

    int e = 0;
    ssize_t offt = 0;
    while (offt < dlen) {
      struct linux_dirent64* de = (struct linux_dirent64*)(db + offt);
      switch (de->d_type) {
        case DT_REG: {
          int fd = openat(dir_fd, de->d_name, O_RDONLY);
          if (fd == -1) {
            LOGE("error opening %s/%s (e: %s) skipping", path, de->d_name, strerror(errno));
            break;
          }

          struct stat64 fs;
          if (fstat64(fd, &fs)) {
            LOGE("error fstating %s/%s %s skipping", path, de->d_name, strerror(errno));
            break;
          }

          _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_ss_insert_file(fd, fs.st_size, path, de->d_name, engine, sf);
          if (e) {
            LOGE("error inserting file %d skipping", e);
            break;
          }

          *path_end = '\0';
        }
        break;
        case DT_DIR: {
          int fd = openat(dir_fd, de->d_name, O_RDONLY | O_DIRECTORY);
          if (fd == -1) {
            LOGE("error opening directory fd %s skipping", strerror(errno));
            break;
          }
          char* end = _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_read_dir(fd, path, end, db, engine, sf);
          *path_end = '\0';
          if (e) {
            return e;
          }
        }
          break;
        case DT_LNK: {
          int fd = openat(dir_fd, de->d_name, O_RDONLY);
          if (fd < 0) {
            LOGE("error openning %s/%s %s", path, de->d_name, strerror(errno));
            break;
          }
          char* end = _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_deal_with_file(fd, path, end, db, engine, sf);
          *path_end = '\0';
        }
        break;
        default: break;
      }

      if (e) {
        LOGW("SKIPPING some files due to errors (%d)", e);
      }

      offt += de->d_off;
    }
  } 
  
  return 0;
}

// int _hsv_load_reg_file(int fd, const char* root, struct hsv_engine_t* engine, struct _hsv_static_files* sf) {
//   int indx = _hsv_static_files_add(sf, fd);
//   if (indx < 0) {
//     LOGW("static files array insert error %d", indx);
//     return 1;
//   }

//   // mapfd_insert_if_not_exists(&engine->static_server.fd_map, );
// }

int fd_daf(struct file_info* data, const char* key, size_t key_len, void* arg) {
  *data = *(struct file_info*)arg;
  return 0;
}

int _hsv_ss_insert_file(int fd, size_t file_size, const char* path, const char* path_end, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf) {
  int indx = _hsv_fixed_file_arr_add(sf, fd);
  if (indx < 0) {
    return -1;
  }

  size_t path_length = path_end - path + 1;

  {
    size_t len = engine->static_server.key_buf_next - engine->static_server.key_buf;
    size_t kbs = engine->static_server.key_buf_size;
    if ((kbs - len) < (path_length)) {
      // TODO add MAP_FAIL check
      mremap(engine->static_server.key_buf, kbs, 2 * kbs, MREMAP_FIXED);
    }
  }
  
  char* dest = engine->static_server.key_buf_next;
  char* end = strcpy(dest, path); 
  engine->static_server.key_buf_next = end+1;

  size_t len = end - dest + 1;

  struct file_info fi = (struct file_info){.fd = indx, .file_size = file_size };

  int e = mapfile_info_insert_if_not_exists(&engine->static_server.fd_map, dest, len, fd_daf, &fi);
  return e;
}

int _hsv_fixed_file_arr_init(struct _hsv_fixed_file_arr *sfiles) {
  size_t bsize = (1 << 21);
  int* buf = (int*) mmap(NULL, bsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
  if (buf == MAP_FAILED) {
    LOGE("a huge page map failed this might be because you have no hugepages %s", strerror(errno));
    return 1;
  }

  *sfiles = (struct _hsv_fixed_file_arr) {.fd_buf = buf, .nr_fd = 0ULL, .max = bsize / sizeof(int)};
  return 0;
}

// on success returns the index (positive) negative on error
int _hsv_fixed_file_arr_add(struct _hsv_fixed_file_arr *sfiles, int fd) {
  if (UNLIKELY(sfiles->nr_fd == sfiles->max)) {
    size_t old_len = sfiles->max * sizeof(int);
    size_t new_len = 2*old_len;
    void* newaddr = mremap(sfiles->fd_buf, old_len, new_len, MREMAP_MAYMOVE);
    if (UNLIKELY(newaddr == MAP_FAILED)) {
      return -1;
    }

    sfiles->max = new_len / sizeof(int);
    sfiles->fd_buf = newaddr;
  }

  size_t indx = sfiles->nr_fd++;
  if (UNLIKELY(indx > INT_MAX)) {
    return -2;
  }
  sfiles->fd_buf[indx] = fd;

  return (int)indx;
}

int _hsv_fixed_file_arr_free(struct _hsv_fixed_file_arr *sfiles) {
  if (munmap(sfiles->fd_buf, sfiles->max * sizeof(int))) {
    LOGW("failed to unmap memory leaked %s", strerror(errno));
    return 1;
  }

  return 0;
}

int _hsv_aquire_request(uint64_t* user_data_io , struct hsv_engine_t* engine) {
  uint64_t user_data = *user_data_io;
  if (UNLIKELY(engine->requests[user_data].flags)) {
    user_data = (engine->dynuser_data + 1) & (HSV_MAXIMUM_REQUEST_NR - 1);
    for (size_t i = user_data; i < HSV_MAXIMUM_REQUEST_NR; ++i) {
      user_data = i & (HSV_MAXIMUM_REQUEST_NR - 1);
      if (!engine->requests[i].flags) {
        *user_data_io = user_data;
        return 0;
      }
    }

    return 1;
  }


  *user_data_io = user_data;
  return 0;
}

void _hsv_handle_accept(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  if (cqe->res < 0) {
    LOGE("failed to accept socket because %s", strerror(-errno));
    return;
  }

  struct io_uring * uring = &engine->uring;

  uint64_t user_data = engine->dynuser_data; 
  if (_hsv_aquire_request(&user_data, engine)) {
    struct io_uring_sqe* send_sqe = io_uring_get_sqe(uring);
    io_uring_prep_send(send_sqe, cqe->res, _hsv_message_too_many_connections, sizeof(_hsv_message_too_many_connections), MSG_NOSIGNAL);
    send_sqe->user_data = _HSV_SEND_ERROR_USER_DATA;
    send_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_CQE_SKIP_SUCCESS | IOSQE_IO_HARDLINK;

    struct io_uring_sqe* close_sqe = io_uring_get_sqe(uring); 
    io_uring_prep_close_direct(close_sqe, cqe->res);
    close_sqe->user_data = _HSV_CLOSE_ERROR_USER_DATA;
    close_sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    return;
  }
  engine->requests[user_data] = (struct _hsv_request)
      { .flags = _HSV_REQUSET_FLAG_INFLIGHT, .asock_indx = cqe->res, .current_size = 0, .buffers = {UINT64_MAX} };
  

  engine->dynuser_data = (engine->dynuser_data + 1) & (HSV_MAXIMUM_REQUEST_NR - 1);

  struct io_uring_sqe* sqe = io_uring_get_sqe(uring);
  io_uring_prep_read(sqe, cqe->res, NULL, INPUT_URING_INPUT_BUF_SIZE, 0);
  sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
  sqe->user_data = _HSV_READ_USER_DATA_BIT | user_data;
  sqe->buf_group = INPUT_URING_INPUT_BUF_GID;
}

void _hsv_handle_read(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
    LOGW("the CQE shoud use a buffer", NULL);
    exit(1);
  }

  uint16_t buf_id = cqe->flags >> 16;

  if (cqe->res < 0) {
    // TODO send error
    LOGW("read failed for %llu with %s", cqe->user_data, strerror(-cqe->res));
    struct io_uring_sqe* close_sqe = io_uring_get_sqe(&engine->uring); 
    io_uring_prep_close_direct(close_sqe, cqe->res);
    close_sqe->user_data = _HSV_CLOSE_ERROR_USER_DATA;
    close_sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    return;
  }

  if (cqe->res < 4) {
    LOGW("HTTP request too short: user_data: %llu", cqe->user_data);

    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  char* buffer = (char*)engine->static_server.buf_ring_backing + buf_id * INPUT_URING_INPUT_BUF_SIZE; 
  static const uint32_t get_req_start = (((((('G' << 8) + 'E') << 8) + 'T') << 8) + ' ');

  if ((*(uint32_t*)buffer) != get_req_start) {
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  char* path_start = buffer + 4;
  char* ptr = path_start;
  while (*(ptr) != ' ') { ptr++; }

  static const char http_version_string[] = "HTTP/1.1\n";
  if (ptr - buffer + sizeof(http_version_string) < cqe->res) {
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  size_t path_len = ptr - path_start;

  if (memcmp(++ptr, http_version_string, sizeof(http_version_string) -1)) {
    // is not an HTTP/1.1 request
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  struct mapfile_info_t* fdmap = &engine->static_server.fd_map;
  struct mapfile_info_entry* entry = mapfile_info_get(fdmap, path_start, path_len);
  if (entry == NULL) {
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  static const char ok_response_start[] = "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: ";
  memcpy(buffer, ok_response_start, sizeof(ok_response_start) - 1);  
  size_t max_len = INPUT_URING_INPUT_BUF_SIZE - sizeof(ok_response_start)-1;
  int len = snprintf(buffer + sizeof(ok_response_start), max_len, "%li", entry->data.file_size);
  if (len < 0 || len >= max_len) {
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  size_t buf_len = sizeof(ok_response_start) + len;
  buffer[buf_len++] = '\n';
  buffer[buf_len] = '\n';  

  size_t req_indx = cqe->user_data & _HSV_DYN_USER_DATA_MASK;
  int req_sock_fdi = engine->requests[req_indx].asock_indx;
  struct io_uring_sqe* header_sqe = io_uring_get_sqe(&engine->uring);
  io_uring_prep_send(header_sqe, req_sock_fdi, buffer, buf_len, MSG_NOSIGNAL);
  header_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_CQE_SKIP_SUCCESS_BIT | IOSQE_IO_LINK;

  struct io_uring_sqe* body_sqe = io_uring_get_sqe(&engine->uring);
  // io_uring_prep_send_file()
}
