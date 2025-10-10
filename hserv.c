#include "_hserv.h"
// it doesn't much matter but in the futre I might want to use the weak attribute to not have these #ifndef…
#ifndef MAP_FILE_INFO_IMPL
#define MAP_FILE_INFO_IMPL
MAP_IMPL(file_info)
#endif

// this is set much higher then needed but that is OK
uint64_t hsv_io_uring_buffer_ids_min_free = 33; 

int hsv_init(struct hsv_engine_t* engine, struct hsv_params* params) {
  // sig pipe is stupid god I whish Linux had SO_NOSIGPIPE
  // this potentionaly breaks user code but we don't want to exit on SIGPIPE
  // and we can't just use send with MSG_NOSIGNAL :(
  signal(SIGPIPE, SIG_IGN);

  memset(engine->requests, 0, sizeof(engine->requests));
  engine->dynuser_data = 0;

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

  if (_hsv_ss_key_buffer_init(engine)) {
    LOGD("failed to allocate static file server map key buffer: %s", strerror(errno));
    return -1;
  }
  
  int ret = UINT8_MAX;
  if (mapfile_info_init(&engine->static_server.fd_map, 4096)) {
    ret = -1;
    goto dealloc_ss_key_buffer;
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

  // each request has a pipe to do zero copy file send hence 3 * MAX_REQUESTS_NR (1 socket, 1 pipe input, 1 pipe output)
  size_t min_ff_buf_size = sf.nr_fd + (3 * HSV_MAXIMUM_REQUEST_NR) + HSV_IO_URING_FREE_FIXED_FD_NR; // + HSV_IO_URING_ENTERIES_NR;
  size_t ff_buf_dyn_start = sf.nr_fd + (2 * HSV_MAXIMUM_REQUEST_NR) + HSV_IO_URING_DYN_ENTERIES_OFFSET;
  LOGT("min io uring fixed file buffer size %zu max is %zu", min_ff_buf_size, sf.max);
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

  {
    struct rlimit64 limit;
    if (getrlimit64(RLIMIT_MEMLOCK, &limit)) {
      LOGE("failed to get memory lock limit: %s", strerror(errno));
      exit(1);
    }

    size_t needed = sf.max * sizeof(int);
    LOGT("memlock: soft_limit=%llu hard_limit=%llu needed=%zu", limit.rlim_cur, limit.rlim_max, needed);
    if (needed < limit.rlim_cur) {
      if (needed > limit.rlim_max) {
        LOGE("need to memlock more memory then possible use `sudo ulimi -l %zu`", needed);
        // TODO do proper error handeling
        exit(1);
      } else {
        limit.rlim_cur = limit.rlim_max;
        if (setrlimit64(RLIMIT_MEMLOCK, &limit)) {
          LOGE("failed to set RLIMIT_MEMLOCK: %s", strerror(errno));
          exit(1);
        }
      }
    }
  }  

  bool pipe_set_error_not_printed = true;
  engine->fixed_file_offset = sf.nr_fd;
  size_t mstatic_end = sf.nr_fd + (2 * HSV_MAXIMUM_REQUEST_NR);
  for (size_t i = sf.nr_fd; i < mstatic_end; i += 2) {
    // LOGT("putting pipe at index %zu", i);
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
    int pipe_size = fcntl64(*(sf.fd_buf + i), F_SETPIPE_SZ, params->static_server.pipe_size);
    if (pipe_size != params->static_server.pipe_size && pipe_set_error_not_printed ) {
      pipe_set_error_not_printed = false;
      LOGW("failed to set pipe [%zu, %llu] size to %d is %d: %s", i, HSV_MAXIMUM_REQUEST_SIZE, params->static_server.pipe_size, pipe_size, strerror(errno));
    }
  }

  for (size_t i = mstatic_end; i < sf.max; ++i) {
    sf.fd_buf[i] = -1;
  }

  // LOGD("file descriptors of files (nr: %zu)", sf.nr_fd);
  // for (size_t i = 0; i < sf.nr_fd; ++i) {
  //   printf("%d\t", sf.fd_buf[i]);
  // }
  // putchar('\n');
  

  // unsigned int flags = IORING_SETUP_COOP_TASKRUN | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_CQE32 | IORING_SETUP_R_DISABLED | IORING_SETUP_SQE128 | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY | IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER;
  unsigned int flags = IORING_SETUP_CQE32 | IORING_SETUP_R_DISABLED | IORING_SETUP_SQE128 | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQPOLL ;
  struct io_uring* uring = &engine->uring;
  ret = io_uring_queue_init(HSV_IO_URING_ENTERIES_NR, uring, flags);
  if (ret) {
    LOGE("queue init failed %s (return: %d)", strerror(-errno), ret);
    goto dealloc_ring_init_err;
  }


  LOGT("trying to register %u files (needs %zuB)", sf.max, sf.max * sizeof(int));
  ret = io_uring_register(uring->ring_fd, IORING_REGISTER_FILES, sf.fd_buf, sf.max);
  if (ret) {
    LOGE("register files error %s", strerror(-ret));
    goto dealloc_w_ring;
  }

  if (io_uring_register_file_alloc_range(uring, ff_buf_dyn_start, sf.max - ff_buf_dyn_start)) {
    LOGE("iouring register file alloc range failed %s", strerror(errno));
    ret = 1;
    goto dealloc_w_ring;
  }

  struct io_uring_buf_ring *ibufring = io_uring_setup_buf_ring(uring, INPUT_URING_INPUT_BUF_NR, INPUT_URING_INPUT_BUF_GID, 0, &ret);
  if (ret) {
    LOGE("iouring pbuf ring register error %d %s", ret, strerror(errno));
    goto dealloc_w_ring;
  }
  engine->input_buffer_ring = ibufring;

  void* buf_ring_backing = mmap(NULL, INPUT_URING_INPUT_BUF_BACKING_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_SMALL_HUGEMAP_MMAP_FLAGS, -1, 0);
  if (buf_ring_backing == MAP_FAILED) {
    LOGE("iouring input buffer ring backing allocation error size: %llu (this allocation may be using hugepages do you have some?)", INPUT_URING_INPUT_BUF_BACKING_SIZE);
    goto dealloc_w_ring;
  }
  engine->static_server.buf_ring_backing = buf_ring_backing;
  for (uint16_t i = 0; i < INPUT_URING_INPUT_BUF_NR; ++i) {
    struct io_uring_buf* urb = ibufring->bufs + i;
    *urb = (struct io_uring_buf) {.bid = i, .addr = (__u64)(buf_ring_backing + i * INPUT_URING_INPUT_BUF_SIZE), .len = INPUT_URING_INPUT_BUF_SIZE, .resv = 0U};
  }
  io_uring_buf_ring_init(ibufring);
  io_uring_buf_ring_advance(ibufring, INPUT_URING_INPUT_BUF_NR);

  struct io_uring_sqe* accept4_sqe = io_uring_get_sqe(uring);
  struct io_uring_sqe* accept6_sqe = io_uring_get_sqe(uring);
  io_uring_prep_multishot_accept_direct(accept4_sqe, ipv4sock, NULL, 0, 0);
  accept4_sqe->user_data = OP_USER_DATA(_HSV_ROP_IPV4_ACCEPT, 0);
  // accept4_sqe->file_index = IORING_FILE_INDEX_ALLOC;

  io_uring_prep_multishot_accept_direct(accept6_sqe, ipv6sock, NULL, 0, 0);
  accept4_sqe->user_data = OP_USER_DATA(_HSV_ROP_IPV6_ACCEPT, 0);
  // accept4_sqe->file_index = IORING_FILE_INDEX_ALLOC;

  if (io_uring_enable_rings(uring)) {
    LOGE("Failed to enable rings", NULL);
    exit(1);
  }

  if (2 != io_uring_submit(uring)) {
    LOGE("two sockets should have SQEs", NULL);
    exit(1);
  }

  for (size_t i = 0; i < HSV_MAXIMUM_REQUEST_NR; ++i) {
    struct hsv_request* request = engine->requests;
    request->buffers[0] = HSV_REQUEST_BUFFER_ARRAY_ENDING;
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
  dealloc_ss_key_buffer:
  _hsv_ss_key_buffer_free(engine);
  return ret;
}

int hsv_serve(struct hsv_engine_t* engine) {
  while (true) {
    LOGI("START OF TICK", NULL);
    engine->input_buffer_buf_offset = 0;
    struct io_uring_cqe* cqe;
    int e = io_uring_wait_cqe(&engine->uring, &cqe);
    if (e) {
      return -1;
    }

    unsigned head;
    unsigned nr = 0U;
    io_uring_for_each_cqe(&engine->uring, head, cqe) {
      switch (GET_OP(cqe->user_data)) {
        case _HSV_ROP_IPV6_ACCEPT:
          LOGD("ACCEPTED A IPV6 socket", NULL);
        case _HSV_ROP_IPV4_ACCEPT:  
          _hsv_handle_accept(engine, cqe);  
        break;
        case _HSV_ROP_READ:
          _hsv_handle_read(engine, cqe);
        break;
        case _HSV_ROP_INITIAL_SEND:
          LOGD("initial send: req=%llu, res=%d", GET_DYN_USER_DATA(cqe->user_data), cqe->res);
          _hsv_handle_initial_send(engine, cqe);
        break;
        case _HSV_ROP_SEND_FILE_IN_PIPE:
          LOGT("file in pipe: req=%llu, res=%d", GET_DYN_USER_DATA(cqe->user_data), cqe->res);
          // let it be handled in the out pipe
          // else {
          //   LOGW("send file in pipe error: %d (%s) req=%llu", cqe->res, strerror(-cqe->res), GET_DYN_USER_DATA(cqe->user_data));
          //   _hsv_close_socket(engine, cqe->user_data & _HSV_DYN_USER_DATA_MASK);
          // }
        break;
        case _HSV_ROP_SEND_FILE_OUT_PIPE:
          // LOGD("file out pipe: req=%llu, res=%d(%s)", GET_DYN_USER_DATA(cqe->user_data), cqe->res, strerror(-cqe->res));
          _hsv_handle_send_file_out_pipe(engine, cqe);
        break;
        case _HSV_ROP_CLOSE_SOCKET:
          _hsv_handle_socket_close_cqe(engine, cqe);
        break;
        case _HSV_ROP_SEND_ERROR:
          LOGW("error sending error message to %llu", cqe->user_data & _HSV_DYN_USER_DATA_MASK);
        break;
        case _HSV_ROP_CLOSE_SOCKET_IMIDIATE:
          LOGW("failed to close a socket that was above the accept limit sock_indx=0x%llx", GET_DYN_USER_DATA(cqe->user_data));

        default:
          LOGW("user data does not match any operation %llx", cqe->user_data);
      }
      nr++;
    }  
    if (engine->input_buffer_buf_offset) {
      io_uring_buf_ring_advance(engine->input_buffer_ring, engine->input_buffer_buf_offset);
    }
    io_uring_cq_advance(&engine->uring, nr);
    _HSV_IO_URING_SUBMIT(engine);
    LOGI("END OF TICK", NULL);
  }
}

void _hsv_handle_initial_send(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  uint64_t req_indx = GET_DYN_USER_DATA(cqe->user_data);
  struct hsv_request* request = &engine->requests[req_indx];
  _hsv_free_request_buffers(engine, request);
}

void _hsv_handle_send_file_out_pipe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  if (UNLIKELY(cqe->res < 0)) {
    LOGW("send file out pipe error: %d (%s)", cqe->res, strerror(-cqe->res));
    return;
  }

  uint64_t req_indx = GET_DYN_USER_DATA(cqe->user_data);

  struct hsv_request* request = &engine->requests[req_indx];

  __off64_t offset = cqe->res + request->file_sending.file_offset;
  request->file_sending.file_offset = offset;
  __off64_t file_size = request->file_sending.file->file_size;

  if (UNLIKELY(offset == file_size)) {
    request->file_sending.file = NULL;
    _hsv_enqueue_read(engine, request, req_indx);

    return;
  };

  LOGT("sending next chunk: req=%llu, offset=%ld", req_indx, offset);
  _hsv_send_file_chunk(engine, request, req_indx, offset); 
}

int _hsv_send_file_chunk(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx, __off64_t offset) {
  struct io_uring_sqe* body_in_sqe = _hsv_io_uring_get(engine);
  struct io_uring_sqe* body_out_sqe = _hsv_io_uring_get(engine);  

  int pipe_indx_out = engine->fixed_file_offset + 2 * req_indx;
  int pipe_indx_in = pipe_indx_out + 1;

  int file_indx = request->file_sending.file->fd;
  __off64_t file_size = request->file_sending.file->file_size;
  uint64_t size = file_size - offset;

  io_uring_prep_splice(body_in_sqe, file_indx, offset, pipe_indx_in, -1, size, SPLICE_F_FD_IN_FIXED);
  body_in_sqe->flags |= IOSQE_FIXED_FILE; // | IOSQE_CQE_SKIP_SUCCESS_BIT;
  body_in_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_IN_PIPE, req_indx);

  io_uring_prep_splice(body_out_sqe, pipe_indx_out, -1, request->asock_indx, -1, size, SPLICE_F_FD_IN_FIXED);
  body_out_sqe->flags |= IOSQE_FIXED_FILE;
  body_out_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_OUT_PIPE, req_indx);

  return 0;
}

static int _hsv_deal_with_file(int fd, const char* path, char* path_end, struct _hsv_dents_buffers* dents_buffer, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf) {
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
      LOGW("file load (%s: inode=%lu): unservable file type", path, fs.st_ino);
      return 2;
      break;
  } 

  return e;
}

int _hsv_load_files(struct hsv_params* params, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr *sf) {
  struct _hsv_dents_buffers dents_buffers;
  int e;
  if ((e = _hsv_dents_buffers_init(&dents_buffers))) {
    return 1;
  }

  char* path_buf = mmap(NULL, HSV_STATIC_PATH_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  for (size_t i = 0; i < params->static_server.nr_dirs; ++i) {
    char* ipath = params->static_server.dirs[i];
    char* end = stpcpy(path_buf, *ipath == '.' ? ipath+1 : ipath);
    int fd = open(ipath, O_RDONLY);
    if (fd == -1) {
      LOGE("failed to open root directory %s", params->static_server.dirs[i]);
      return 1;
    }
    int e;
    if ((e = _hsv_deal_with_file(fd, path_buf, end, &dents_buffers, engine, sf))) {
      LOGE("problem with %s (%d)", path_buf, e);
    }
  }

  _hsv_dents_free_buffers(&dents_buffers);
  // TODO check for errors on unmaps
  if (munmap(path_buf, HSV_STATIC_PATH_BUFFER_SIZE)) {
    LOGW("failed to deallocate path buffer: %s", strerror(errno));
  }
  return 0;
}


int _hsv_read_dir(int dir_fd, const char* path, char* path_end, struct _hsv_dents_buffers* dbs, struct hsv_engine_t* engine, struct _hsv_fixed_file_arr* sf) {
  LOGT("reading dir %s\n", path);
  void* db;
  if (!(db = _hsv_dents_get(dbs))) {
    LOGE("failed to accquire a dents buffer skipping direcotory %s", path);
    return 1;
  }
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
      LOGD("processing file: %s/%s", path, de->d_name);
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

          char* new_end = _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_ss_insert_file(fd, fs.st_size, path, new_end, engine, sf);
          if (e) {
            LOGE("error inserting file %d skipping", e);
            break;
          }

          *path_end = '\0';
        }
        break;
        case DT_DIR: {
          // if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
          if (_hsv_read_dir_should_ingnore_file(de->d_name)) {
            LOGT("throwing out %s/%s", path, de->d_name);
            e = 0;
            break;
          }
          LOGT("reading dir %s", de->d_name);
          int fd = openat(dir_fd, de->d_name, O_RDONLY | O_DIRECTORY);
          if (fd == -1) {
            LOGE("error opening directory fd %s skipping", strerror(errno));
            e = -1;
            break;
          }
          char* end = _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_read_dir(fd, path, end, dbs, engine, sf);
          *path_end = '\0';
          if (e) {
            return e;
          }
        }
          break;
        case DT_LNK: {
          LOGT("dt link %s", de->d_name);
          int fd = openat(dir_fd, de->d_name, O_RDONLY);
          if (fd < 0) {
            LOGE("error openning %s/%s %s", path, de->d_name, strerror(errno));
            break;
          }
          char* end = _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_deal_with_file(fd, path, end, dbs, engine, sf);
          *path_end = '\0';
        }
        break;
        case DT_UNKNOWN: {
          LOGT("DT unknown %s", de->d_name);
          int fd = openat(dir_fd, de->d_name, O_RDONLY);
          char* end = _hsv_add_to_path(path, path_end, de->d_name);
          e = _hsv_deal_with_file(fd, path, end, dbs, engine, sf);
          *path_end = '\0';
        }
        break;
        default: break;
      }

      if (e) {
        LOGW("SKIPPING some files due to errors (%d)", e);
      }

      offt += de->d_reclen;
    }
  } 

  _hsv_dents_free_buffer(dbs);
  
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

  size_t path_length = path_end - path;

  {
    size_t len = engine->static_server.key_buf_next - engine->static_server.key_buf;
    size_t kbs = engine->static_server.key_buf_size;
    if ((kbs - len) < (path_length)) {
      // TODO add MAP_FAIL check
      mremap(engine->static_server.key_buf, kbs, 2 * kbs, MREMAP_FIXED);
    }
  }
  
  char* dest = engine->static_server.key_buf_next;
  char* end = stpncpy(dest, path, path_length); 
  engine->static_server.key_buf_next = end;

  // size_t len = end - dest + 1;

  struct file_info fi = (struct file_info){.fd = indx, .file_size = file_size };

  LOGT("inserting: %.*s", (int)path_length, dest);
  int e = mapfile_info_insert_if_not_exists(&engine->static_server.fd_map, dest, path_length, fd_daf, &fi);
  return e;
}

int _hsv_fixed_file_arr_init(struct _hsv_fixed_file_arr *sfiles) {
  size_t bsize = (1 << 14);
  int* buf = (int*) mmap(NULL, bsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED) {
    LOGE("a huge page map failed this might be because you have no hugepages %s", strerror(errno));
    return 1;
  }

  *sfiles = (struct _hsv_fixed_file_arr) {.fd_buf = buf, .nr_fd = 0ULL, .max = bsize / sizeof(int)};
  return 0;
}

// on success returns the index (positive) negative on error
int _hsv_fixed_file_arr_add(struct _hsv_fixed_file_arr *sfiles, int fd) {
  LOGT("adding to fixed file array fd: %d", fd);
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

  LOGT("added to fixed file_array fd: %d", fd);
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
    struct io_uring_sqe* close_sqe = io_uring_get_sqe(uring); 
    // WARN TODO check for get sqe error
    io_uring_prep_send(send_sqe, cqe->res, _hsv_message_too_many_connections, sizeof(_hsv_message_too_many_connections), MSG_NOSIGNAL);
    send_sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_SEND_ERROR, user_data);
    // it is ok not to send cqe because it does not use a buffer as it's backing store
    send_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_CQE_SKIP_SUCCESS | IOSQE_IO_HARDLINK;

    io_uring_prep_close_direct(close_sqe, cqe->res);
    close_sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_CLOSE_SOCKET_IMIDIATE, cqe->res);
    close_sqe->flags |= IOSQE_CQE_SKIP_SUCCESS_BIT;
    return;
  }
  struct hsv_request* request = &engine->requests[user_data];
  *request = (struct hsv_request)
      { .flags = _HSV_REQUSET_FLAG_INFLIGHT, .asock_indx = cqe->res, .current_size = 0, .buffers = {HSV_REQUEST_BUFFER_ARRAY_ENDING} };
  

  engine->dynuser_data = (engine->dynuser_data + 1) & (HSV_MAXIMUM_REQUEST_NR-1);
  LOGT("new dyn user data: %llu", engine->dynuser_data);

  struct io_uring_sqe* sqe = _hsv_enqueue_read(engine, request, user_data);
  LOGT("new request %lu socket: %d (readOP{user_data=%llx})",user_data, cqe->res, sqe->user_data);
}

void _hsv_dprint_requests(struct hsv_engine_t* engine) {
  LOGD("REQUESTS START", NULL);

  for (size_t i = 0; i < HSV_MAXIMUM_REQUEST_NR; ++i) {
    struct hsv_request* request = engine->requests + i;
    printf("\t%zu: flag=%u, sock=%d, size: %zu, file_sending={file=%d, file_offset=%ld}, buffers=[%d, %d]\n",
           i, request->flags, request->asock_indx, request->current_size, request->file_sending.file ? request->file_sending.file->fd : -1,
           request->file_sending.file_offset, request->buffers[0], request->buffers[1]);
  }

  LOGD("REQUESTs END", NULL);
}

void _hsv_handle_read(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {

  if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
    LOGE("the CQE shoud use a buffer: %s", strerror(-cqe->res));
    exit(1);
  }

  size_t req_indx = GET_DYN_USER_DATA(cqe->user_data);
  uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  LOGT("reading request %lu (res=%d, bufid=%u, cqe_flags=%x, ud=%llx)", req_indx, cqe->res, buf_id, cqe->flags, cqe->user_data);
  char* buffer = (char*)engine->static_server.buf_ring_backing + buf_id * INPUT_URING_INPUT_BUF_SIZE; 

  if (cqe->res == EPIPE || cqe->res == 0) {
    _hsv_ibufring_return(engine, buffer, buf_id);
    LOGT("closing request %llu", req_indx);
   _hsv_close_socket(engine, req_indx);
   return;
  }

  if (cqe->res < 0) {
    // TODO send error
    LOGW("read failed for %llu with %s", cqe->user_data, strerror(-cqe->res));
    struct io_uring_sqe* close_sqe = io_uring_get_sqe(&engine->uring); 
    io_uring_prep_close_direct(close_sqe, cqe->res);
    close_sqe->user_data = OP_USER_DATA(_HSV_ROP_CLOSE_SOCKET, req_indx);

    _hsv_ibufring_return(engine, buffer, buf_id);
    return;
  }

  if (cqe->res < 4) {
    LOGW("HTTP request too short: user_data: %llu", cqe->user_data);

    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  static const uint32_t get_req_start = (((((('G' << 8) + 'E') << 8) + 'T') << 8) + ' ');

  uint32_t type_str = ((((((*buffer) << 8) + *(buffer+1)) << 8) + *(buffer+2)) << 8) + *(buffer+3);
  if (type_str != get_req_start) {
    LOGW("invalid request %s", buffer);
    _hsv_dprint_requests(engine);
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  char* path_start = buffer + 4;
  char* ptr = path_start;
  while (*(ptr) != ' ') { ptr++; }

  static const char http_version_string[] = "HTTP/1.1\r\n";
  /// what was this for I dont know
  // if (ptr - buffer + sizeof(http_version_string) > cqe->res) {
  //   LOGE("unprocesabble HTTP/1.1 request: too short\n```%s```", buffer);
  //   // TODO send error & close socket & return the buffer to the pool
  //   exit(1);
  // }

  size_t path_len = ptr - path_start;

  if (memcmp(++ptr, http_version_string, sizeof(http_version_string) -1)) {
    LOGE("invalid http version", NULL);
    // is not an HTTP/1.1 request
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  struct mapfile_info_t* fdmap = &engine->static_server.fd_map;
  struct mapfile_info_entry* entry = mapfile_info_get(fdmap, path_start, path_len);
  if (entry == NULL) {
    LOGE("no such file %.*s", (int)path_len, path_start);
    // LOGE("internal state error reading from a socket with not request entry found", NULL);
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }

  static const char ok_response_start[] = "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: ";
  memcpy(buffer, ok_response_start, sizeof(ok_response_start) - 1);  
  size_t max_len = INPUT_URING_INPUT_BUF_SIZE - sizeof(ok_response_start)-1;
  int len = snprintf(buffer + sizeof(ok_response_start) -1, max_len, "%li\n\n", entry->data.file_size);
  if (len < 0 || len >= max_len) {
    // TODO send error & close socket & return the buffer to the pool
    exit(1);
  }


  size_t buf_len = sizeof(ok_response_start) + len;
  int req_sock_fdi = engine->requests[req_indx].asock_indx;

  // LOGT("initial response for request %lu (sock=%d): %s", req_indx, req_sock_fdi, buffer);

  struct io_uring_sqe* header_sqe = io_uring_get_sqe(&engine->uring);
  struct io_uring_sqe* body_in_sqe = io_uring_get_sqe(&engine->uring);
  struct io_uring_sqe* body_out_sqe = io_uring_get_sqe(&engine->uring);

  io_uring_prep_send(header_sqe, req_sock_fdi, buffer, buf_len, MSG_NOSIGNAL);
  header_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK; // | IOSQE_CQE_SKIP_SUCCESS_BIT;
  header_sqe->user_data = OP_USER_DATA(_HSV_ROP_INITIAL_SEND, req_indx);

  int pipe_indx_out = engine->fixed_file_offset + 2 * req_indx;
  int pipe_indx_in = pipe_indx_out + 1;
  // LOGT("ffoffset=%d pipe in %d, pipe out %d", engine->fixed_file_offset, pipe_indx_in, pipe_indx_out);

  io_uring_prep_splice(body_in_sqe, entry->data.fd, 0, pipe_indx_in, -1, entry->data.file_size, SPLICE_F_FD_IN_FIXED);
  body_in_sqe->flags |= IOSQE_FIXED_FILE; // | IOSQE_CQE_SKIP_SUCCESS_BIT;
  body_in_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_IN_PIPE, req_indx);

  io_uring_prep_splice(body_out_sqe, pipe_indx_out, -1, req_sock_fdi, -1, entry->data.file_size, SPLICE_F_FD_IN_FIXED);
  body_out_sqe->flags |= IOSQE_FIXED_FILE;
  body_out_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_OUT_PIPE, req_indx);

  struct hsv_request* request = &engine->requests[req_indx];
  request->buffers[0] = buf_id;
  if (sizeof(request->buffers) / sizeof(int) > 1) {
    request->buffers[1] = HSV_REQUEST_BUFFER_ARRAY_ENDING;
  }
  request->file_sending.file = &entry->data;
  request->file_sending.file_offset = 0;

  // LOGT("using the file with fixed fd=%d of length %zu", entry->data.fd, entry->data.file_size);
  // LOGT("sent file ffindx=%d of size %zu to %d", entry->data.fd, entry->data.file_size, req_sock_fdi);
}

void _hsv_handle_socket_close_cqe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  uint64_t req_indx = GET_DYN_USER_DATA(cqe->user_data);
  struct hsv_request* request = &engine->requests[req_indx];

  if (cqe->res < 0) {
    LOGE("failed to close socket of %llu (user_data=0x%llx) is closed: res=%d flags=%x", GET_DYN_USER_DATA(cqe->user_data), cqe->user_data, cqe->res, cqe->flags);
  }

  request->flags = 0U;
  request->file_sending.file = NULL;
}

void _hsv_close_socket(struct hsv_engine_t* engine, uint64_t request_index) {
  struct io_uring_sqe* cs_sqe;
  get_cs_sqe:
  cs_sqe = io_uring_get_sqe(&engine->uring);
  if (!cs_sqe) {
    _HSV_IO_URING_SUBMIT(engine);
    goto get_cs_sqe;
  }

  struct hsv_request* request = &engine->requests[request_index];
  _hsv_free_request_buffers(engine, request);
  io_uring_prep_close_direct(cs_sqe, request->asock_indx);
  io_uring_sqe_set_data64(cs_sqe, OP_USER_DATA(_HSV_ROP_CLOSE_SOCKET, request_index));

  LOGT("closing socket %d of %u", request->asock_indx, request_index);
}

void _hsv_ibufring_return(struct hsv_engine_t* engine, char* buffer, uint16_t buf_id) {
  int mask = io_uring_buf_ring_mask(INPUT_URING_INPUT_BUF_NR);
  io_uring_buf_ring_add(engine->input_buffer_ring, buffer, INPUT_URING_INPUT_BUF_SIZE, buf_id, mask, engine->input_buffer_buf_offset++);
}

char* _hsv_add_to_path(const char* path, char* path_end, char* fname) {
  *path_end = '/';
  char* end = stpcpy(path_end+1, fname);

  return end;
}

int _hsv_dents_buffers_init(struct _hsv_dents_buffers* db) {
  void* dents_buffer = mmap(NULL, 3 * _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS, -1, 0);
  if (dents_buffer == MAP_FAILED) {
    LOGE("it is very likely a mmap failed because you have not enabled hugepages: %s", strerror(errno));
    return 1;
  }
  db->buffers[0] = dents_buffer;
  db->buffers[1] = dents_buffer + _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE;
  db->buffers[2] = dents_buffer + 2 * _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE;
  size_t dblen = 3;

  // memset(db->buffers + dblen, 0, sizeof(void*) * (_HSV_DENTS_BUFFERS_SIZE - db->len));
  for (size_t i = dblen; i < _HSV_DENTS_BUFFERS_SIZE; ++i) {
    db->buffers[i] = NULL;
  }

  db->len = 0;

  return 0;
}
void* _hsv_dents_get(struct _hsv_dents_buffers* db) {
  if (db->len == _HSV_DENTS_BUFFERS_SIZE) {
    return NULL;
  }

  if (db->buffers[db->len]) {
      db->len++;
      return db->buffers[db->len];
  }

  void* dents_buffer = mmap(NULL, _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS, -1, 0);
  if (dents_buffer == MAP_FAILED) {
    LOGE("it is very likely a mmap failed because you have not enabled hugepages: %s", strerror(errno));
    return NULL;
  }
  
  return (db->buffers[db->len++] = dents_buffer);
}

void _hsv_dents_free_buffer(struct _hsv_dents_buffers* db) {
  db->len -= 1;
}

void _hsv_dents_free_buffers(struct _hsv_dents_buffers* db) {
  for (size_t i = 0; i < _HSV_DENTS_BUFFERS_SIZE; ++i) {
    if (!db->buffers[i]) {
      return;
    }

    if (munmap(db->buffers[i], _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE)) {
      LOGW("memory leak: faild to munmap memmory (%s) at %p of expected size %llu", strerror(errno), db->buffers[i], _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE);
    }
  }
}

int _hsv_ss_key_buffer_init(struct hsv_engine_t* engine) {
  char* key_buf = mmap(NULL, _HSV_SS_KEY_BUFFER_INITIAL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_SS_KEY_BUFFER_INITIAL_MMAP_HPAGE_FLAGS, -1, 0);
  if (key_buf == MAP_FAILED) {
    return 1;
  }

  LOGT("key buffer start at %p ends at %p", key_buf, key_buf + _HSV_SS_KEY_BUFFER_INITIAL_SIZE);
  engine->static_server.key_buf = key_buf;
  engine->static_server.key_buf_next = key_buf;
  engine->static_server.key_buf_size = _HSV_SS_KEY_BUFFER_INITIAL_SIZE;  

  return 0;
}

int _hsv_ss_key_buffer_free(struct hsv_engine_t* engine) {
  int r;
  if ((r = munmap(engine->static_server.key_buf, engine->static_server.key_buf_size))) {
    LOGW("memory leak failed to munmap static_server.key_buffer: %s", strerror(errno));
  }
  return r;
}

// dname must be located at a address that can be read up to dname + 2
int _hsv_read_dir_should_ingnore_file(char* dname) {
  static const uint32_t this = '.' << 2 * sizeof(char);
  static const uint32_t super = (('.' << sizeof(char)) + '.') << sizeof(char);
  uint32_t name = ((((*dname) << sizeof(char)) + *(dname+1)) << sizeof(char)) + *(dname+2);

  return this == name || super == name;
}

struct io_uring_sqe* _hsv_io_uring_get(struct hsv_engine_t* engine) {
  struct io_uring_sqe* sqe;

  while (!(sqe = io_uring_get_sqe(&engine->uring))) {
    _HSV_IO_URING_SUBMIT(engine);
  }

  return sqe;
}

void _hsv_free_request_buffers(struct hsv_engine_t* engine, struct hsv_request* request) {
  for (uint_fast16_t i = 0; i < sizeof(request->buffers) / sizeof(int); ++i) {
    uint64_t buf_id = request->buffers[i];
    if (buf_id == HSV_REQUEST_BUFFER_ARRAY_ENDING) break;
    void* buf_ptr = engine->static_server.buf_ring_backing + buf_id * INPUT_URING_INPUT_BUF_SIZE;
    _hsv_ibufring_return(engine, buf_ptr, buf_id);
    request->buffers[i] = HSV_REQUEST_BUFFER_ARRAY_ENDING;
  }

  request->current_size = 0;
}

struct io_uring_sqe* _hsv_enqueue_read(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx) {
  struct io_uring_sqe* sqe = io_uring_get_sqe(&engine->uring);
  io_uring_prep_read(sqe, request->asock_indx, NULL, INPUT_URING_INPUT_BUF_SIZE, 0);
  sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
  sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_READ, req_indx);
  sqe->buf_group = INPUT_URING_INPUT_BUF_GID;

  return sqe;
}

