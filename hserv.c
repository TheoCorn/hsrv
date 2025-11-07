#include "__hserv.h"

// it doesn't much matter but in the futre I might want to use the weak attribute to not have these #ifndef…
#ifndef MAP_FILE_INFO_IMPL
#define MAP_FILE_INFO_IMPL
MAP_IMPL(hsv_path_handler)
#endif

// this is set much higher then needed but that is OK
uint64_t hsv_io_uring_buffer_ids_min_free = 33; 

int setup_default_handler(struct hsv_engine_t* engine, struct _hsv_fixed_file_arr *sf) {
  int memfd = memfd_create("default response", 0);
  if (memfd == -1) {
    LOGE("failed to create memfd: %d (%s)", errno, strerror(errno));
    return -1;
  }
  int pipe[2];
  int e = pipe2(pipe, 0);
  if (e) {
    LOGE("failed to create pipe: %d (%s)", errno, strerror(errno));
    close(memfd);
    return -1;
  }

  struct iovec iov;
  iov.iov_base = (void*)_hsv_message_default_response;
  iov.iov_len = _hsv_message_default_response_size;
  ssize_t res = vmsplice(pipe[1], &iov, 1, 0);
  if (res != _hsv_message_default_response_size) {
    LOGE("failed to vmsplice message: %ld, errno=%d (%s)", res, errno, strerror(errno));
    close(memfd);
    close(pipe[0]);
    return -2;
  }
  e = splice(pipe[0], 0, memfd, 0, _hsv_message_default_response_size, 0);
  if (e != _hsv_message_default_response_size) {
    LOGE("failed to splice: %d errno=%d (%s)", e, errno, strerror(errno));
    close(pipe[0]);
    close(memfd);
    return -3;
  }

  if (-1 == close(pipe[0])) {
    LOGW("failed to close pipe: %d (%s)", errno, strerror(errno));
  }

  int fdi = _hsv_fixed_file_arr_add(sf, memfd);
  if (fdi < 0) {
    LOGE("falied to add default handler fd to fixed file array: %d", fdi);
    close(memfd);
    return 1;
  }

  engine->default_handler.flags = 0;
  engine->default_handler.htype = HSV_HANDLER_STATIC_FILE_RAW;
  engine->default_handler.info.raw_ss_path_info.flags = HSV_RAW_STATIC_FILE_PATH_FLAG_NO_HTTP_METHOD_CHECK;
  engine->default_handler.info.raw_ss_path_info.finfo = (struct hsv_file_info) {
    .fd = fdi,
    .file_size = (__off64_t)_hsv_message_default_response_size,
  };

  LOGD("default handler file=%d file_size=%ld", engine->default_handler.info.raw_ss_path_info.finfo.fd, engine->default_handler.info.raw_ss_path_info.finfo.file_size);
  
  return 0;
}

int _hsv_bind_listen(const struct hsv_params* const params, uint16_t port, int *_ipv4sock, int *_ipv6sock) {
  int ipv4sock = -1, ipv6sock = -1;
  int sock_opt = 1;

  if (params->flags[0] & HSV_PARAMS_IPV4_BIND) {
    ipv4sock = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == ipv4sock) {
      return 1;
    }
    setsockopt(ipv4sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
  
    struct sockaddr_in ipv4_addr;
    ipv4_addr.sin_family = AF_INET;
    ipv4_addr.sin_addr = params->address4;
    ipv4_addr.sin_port = htons(port);

    if (bind(ipv4sock, &ipv4_addr, sizeof(struct sockaddr_in))) {
      LOGE("failed to bind ipv4 socket %s", strerror(errno));
      goto close_sock_ret;
    }
    if (listen(ipv4sock, HSV_NET_BACKLOG)) {
      LOGE("failed to listen on IPv4 sock %s", strerror(errno));
      goto close_sock_ret;
    }
  }

  if (params->flags[0] & HSV_PARAMS_IPV6_BIND) {
    ipv6sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (-1 == ipv6sock) {
      goto close_sock_ret;
    }

    setsockopt(ipv6sock, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt));
    setsockopt(ipv6sock, IPPROTO_IPV6, IPV6_V6ONLY, &sock_opt, sizeof(sock_opt));


    struct sockaddr_in6 ipv6_addr;
    ipv6_addr.sin6_family = AF_INET6;
    ipv6_addr.sin6_addr = params->address6;
    ipv6_addr.sin6_port = htons(port);
  
    if (bind(ipv6sock, &ipv6_addr, sizeof(ipv6_addr))) {
      LOGE("failed to bind ipv6 socket %s", strerror(errno));
      goto close_sock_ret;
    }

    if (listen(ipv6sock, HSV_NET_BACKLOG)) {
      LOGE("failed to listen on IPv6 sock %s", strerror(errno));
      goto close_sock_ret;
    }
  }
 

  *_ipv4sock = ipv4sock;
  *_ipv6sock = ipv6sock;
  return 0;

  close_sock_ret:
    if (ipv4sock != -1 && -1 == close(ipv4sock)) {
      LOGW("failed to close ipv6sock fd=%d: %d (%s)", ipv6sock, errno, strerror(errno));
    }
    if (ipv6sock != -1 && -1 == close(ipv6sock)) {
      LOGW("failed to close ipv4sock fd=%d: %d (%s)", ipv4sock, errno, strerror(errno));
    }

  return 1;
}


int hsv_init(struct hsv_engine_t* engine, struct hsv_params* params) {
  int ret = UINT8_MAX;
      
  struct _hsv_fixed_file_arr sf;
  int e;
  if (( e = _hsv_fixed_file_arr_copy(&params->ffile_arr, &sf) )) {
    LOGE("failed to coppy ffa: %d", e);
    return 1;
  }

  if (params->default_handler.htype == HSV_HANDLER_STATIC_FILE_RAW &&
    params->default_handler.info.raw_ss_path_info.finfo.fd == _HSV_DEFAULT_HANDLER_FINFO_FD) {
     if ((ret = setup_default_handler(engine, &sf))) {
       LOGE("failed to set up default handler", NULL);
       goto dealloc_ffa;
     }
  } else {
    engine->default_handler = params->default_handler;
  }

  // sig pipe is stupid god I whish Linux had SO_NOSIGPIPE
  // this potentionaly breaks user code but we don't want to exit on SIGPIPE
  // and we can't just use send with MSG_NOSIGNAL :(
  signal(SIGPIPE, SIG_IGN);

  memset(engine->requests, 0, sizeof(engine->requests));
  engine->dynuser_data = 0;

  // int ipv4sock = -1, ipv6sock = -1, ipv4secsock = -1, ipv6secsock = -1;
  int sockets[4] = {-1, -1, -1, -1};
  const int *ipv4sock = &sockets[0];
  const int *ipv6sock = &sockets[1];
  const int *ipv4secsock = &sockets[2];
  const int *ipv6secsock = &sockets[3];
  if (params->port != HSV_PARAMS_PORT_NO_BIND) {
    if ((ret = _hsv_bind_listen(params, params->port, &sockets[0], &sockets[1]))) {
      LOGE("failed to bind and listen port %u", params->port);
      goto dealloc_ffa;
    }
  }

  if (params->sport != HSV_PARAMS_PORT_NO_BIND) {
    if ((ret = _hsv_bind_listen(params, params->sport, &sockets[2], &sockets[3]))) {
      LOGE("failed to bind and listen secure port %u", params->port);
      goto dealloc_port;
    }

    SSL_library_init();
    SSL_CTX *sslctx = engine->tls.ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(sslctx, params->tls.cert_path, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(sslctx, params->tls.pkey_path, SSL_FILETYPE_PEM);
  }
 
  if (map_hsv_path_handler_init(&engine->path_map, 4096)) {
    ret = -1;
    goto dealloc_ffa;
  }

  for (size_t i = 0; i < params->paths_nr; ++i) {
    const char* const path = params->_pbuf + params->paths_off[i];
    LOGT("path: %s", path);
    // size_t path_len = params->paths_off[i+1] - params->paths_off[i];
    size_t path_len = strlen(path);
    LOGI("inserting into path map %s", path);
    if (map_hsv_path_handler_set(&engine->path_map, path, path_len, &params->path_handlers[i])) {
      goto dealloc_path_map;
    }
  }

  // each request has a pipe to do zero copy file send hence 3 * MAX_REQUESTS_NR (1 socket, 1 pipe input, 1 pipe output)
  size_t min_ff_buf_size = sf.nr_fd + (3 * HSV_MAXIMUM_REQUEST_NR) + HSV_IO_URING_FREE_FIXED_FD_NR; // + HSV_IO_URING_ENTERIES_NR;
  size_t ff_buf_dyn_start = sf.nr_fd + (2 * HSV_MAXIMUM_REQUEST_NR) + HSV_IO_URING_DYN_ENTERIES_OFFSET;
  LOGT("min io uring fixed file buffer size %zu max is %zu", min_ff_buf_size, sf.max);
  if (_hsv_fixed_file_arr_reserve(&sf, min_ff_buf_size)) {
    LOGE("failed to reserve fixed files", NULL);
    exit(1);
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

  /*
    pipe creation using io_uring is aviable in kernel 6.16.x (2025-04-08) but that is
    unreasonably new even for me 
  */
  bool pipe_set_error_not_printed = true;
  engine->fixed_file_offset = sf.nr_fd;
  size_t mstatic_end = sf.nr_fd + (2 * HSV_MAXIMUM_REQUEST_NR);
  for (size_t i = sf.nr_fd; i < mstatic_end; i += 2) {
    // LOGT("putting pipe at index %zu", i);
    retry_pipe:
    int *addr = sf.fd_buf + i;
    if (pipe2(addr, 0)) {
      LOGW("failed to create a pipe ff_indx=%zu, ptr=%p: %s", i, (void*)addr, strerror(errno));
      
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
  engine->buf_ring_backing = buf_ring_backing;
  for (uint16_t i = 0; i < INPUT_URING_INPUT_BUF_NR; ++i) {
    struct io_uring_buf* urb = ibufring->bufs + i;
    *urb = (struct io_uring_buf) {.bid = i, .addr = (__u64)(buf_ring_backing + i * INPUT_URING_INPUT_BUF_SIZE), .len = INPUT_URING_INPUT_BUF_SIZE, .resv = 0U};
  }
  io_uring_buf_ring_init(ibufring);
  io_uring_buf_ring_advance(ibufring, INPUT_URING_INPUT_BUF_NR);

  // dont check if SQEs NULL because the sq ring is free
  if (*ipv4sock != -1) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(uring);
    io_uring_prep_multishot_accept_direct(sqe, *ipv4sock, NULL, 0, 0);
    sqe->user_data = OP_USER_DATA(_HSV_ROP_IPV4_ACCEPT, 0);
  }

  if (*ipv6sock) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(uring);
    io_uring_prep_multishot_accept_direct(sqe, *ipv6sock, NULL, 0, 0);
    sqe->user_data = OP_USER_DATA(_HSV_ROP_IPV6_ACCEPT, 0);
  }

  if (*ipv4secsock != -1) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(uring);
    io_uring_prep_multishot_accept_direct(sqe, *ipv4secsock, NULL, 0, 0);
    sqe->user_data = OP_USER_DATA(_HSV_ROP_IPV4_SEC_ACCEPT, 0);
  } 

  if (*ipv6secsock != -1) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(uring);
    io_uring_prep_multishot_accept_direct(sqe, *ipv6secsock, NULL, 0, 0);
    sqe->user_data = OP_USER_DATA(_HSV_ROP_IPV6_SEC_ACCEPT, 0);
  } 

  if (io_uring_enable_rings(uring)) {
    LOGE("Failed to enable rings", NULL);
    exit(1);
  }

  io_uring_submit(uring);
  //   LOGE("two sockets should have SQEs", NULL);
  //   exit(1);

  for (size_t i = 0; i < HSV_MAXIMUM_REQUEST_NR; ++i) {
    struct hsv_request* request = engine->requests;
    request->buffers[0].type = _HSV_REQUEST_BUFFER_NONE;
  }

  size_t buf_caps[_HSV_MBUFCACHE_NR_SIZES] = {0};
  buf_caps[0] = HSV_MAXIMUM_REQUEST_NR;
  if (_hsv_mbufcache_init(&engine->buf_cache, buf_caps)) {
    LOGE("failed to initilize mbufcache: %d", ret);
    ret = 1;
    goto dealloc_all;
  } 

  // _hsv_fixed_file_arr_free_fds(&sf);
  _hsv_fixed_file_arr_free(&sf);
  return 0;


  dealloc_all:
  dealloc_w_ring:
  dealloc_ring_init_err:
  dealloc_path_map:
  map_hsv_path_handler_free(&engine->path_map);
  // _hsv_ss_key_buffer_free(engine);
  dealloc_port:
  {
    for (int i = 0; i < 4; ++i) {
      if (sockets[i] != -1 && close(sockets[i])) {        
        LOGW("failed to close port %d: %d (%s)", sockets[i], errno, strerror(errno));
      }
    }
  }
  dealloc_ffa:
  _hsv_fixed_file_arr_free(&sf);
  return ret;
}


int hsv_serve(struct hsv_engine_t* engine) {
  while (true) {
    LOGI("START OF TICK", NULL);
    engine->input_buffer_buf_offset = 0;
    struct io_uring_cqe* cqe;
    int e = io_uring_wait_cqe(&engine->uring, &cqe);
    if (e) {
      LOGE("wait cqe failed: %d (%s)", e, strerror(-e));
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
        case _HSV_ROP_IPV6_SEC_ACCEPT:
          LOGD("ACCEPTED A IPV6 socket", NULL);
        case _HSV_ROP_IPV4_SEC_ACCEPT:
          _hsv_handle_sec_accept(engine, cqe);
        break;
        case _HSV_ROP_SSL_WRITE:
          _hsv_handle_ssl_write(engine, cqe);
        break;
        case _HSV_ROP_SSL_READ:
          _hsv_handle_ssl_read(engine, cqe);
        break;
        case _HSV_ROP_SSL_SETSOCKOPT:
          _hsv_handle_ssl_setsockopt(engine, cqe);
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
        break;

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

  LOGT("file out pipe: req=%llu, res=%d", GET_DYN_USER_DATA(cqe->user_data), cqe->res);

  uint64_t req_indx = GET_DYN_USER_DATA(cqe->user_data);

  struct hsv_request* request = &engine->requests[req_indx];

  // if (UNLIKELY(request->file_sending.in_pipe_res != cqe->res)) {
  //   if (request->file_sending.in_pipe_res > cqe->res) {
      
  //   }      
  // }

  struct _hsv_request_data_send_file * const sfd = &request->data.file_sending;
  __off64_t offset = ((__off64_t)cqe->res) + sfd->file_offset;
  sfd->file_offset = offset;
  __off64_t file_size = sfd->file->file_size;

  if (UNLIKELY(offset >= file_size)) {
    sfd->file = NULL;
    _hsv_enqueue_read(engine, request, req_indx);

    return;
  };

  _hsv_send_file_chunk(engine, request, req_indx, offset); 
}

int _hsv_send_file_chunk(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx, __off64_t offset) {
  struct io_uring_sqe* body_in_sqe = _hsv_io_uring_get_sqe(engine);
  struct io_uring_sqe* body_out_sqe = _hsv_io_uring_get_sqe(engine);  

  int pipe_indx_out = engine->fixed_file_offset + 2 * req_indx;
  int pipe_indx_in = pipe_indx_out + 1;

  struct _hsv_request_data_send_file * const sfd = &request->data.file_sending;
  int file_indx = sfd->file->fd;
  __off64_t file_size = sfd->file->file_size;
  uint64_t size = (1ULL << 21);

  LOGT("sending next chunk: req=%llu, offset=%ld, len=%llu (file_size=%ld)", req_indx, offset, size, file_size);

  io_uring_prep_splice(body_in_sqe, file_indx, offset, pipe_indx_in, -1, size, SPLICE_F_FD_IN_FIXED);
  body_in_sqe->flags |= IOSQE_FIXED_FILE; // | IOSQE_CQE_SKIP_SUCCESS_BIT;
  body_in_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_IN_PIPE, req_indx);

  io_uring_prep_splice(body_out_sqe, pipe_indx_out, -1, request->asock_indx, -1, size, SPLICE_F_FD_IN_FIXED);
  body_out_sqe->flags |= IOSQE_FIXED_FILE;
  body_out_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_OUT_PIPE, req_indx);

  return 0;
}

int fd_daf(struct hsv_file_info* data, const char* key, size_t key_len, void* arg) {
  *data = *(struct hsv_file_info*)arg;
  return 0;
}

int _hsv_fixed_file_arr_init(struct _hsv_fixed_file_arr *sfiles) {
  size_t bsize = (1 << 14);
  int memfd = memfd_create("hsv_params_static_files", 0);
  if (memfd == -1) {
    LOGW("memfd_create failed: %d (%s)", errno, strerror(errno));
    return 1;
  }
  if (ftruncate64(memfd, bsize)) {
    LOGW("ftruncate failed %d (%s)", errno, strerror(errno));
    return 1;
  }
  int* buf = (int*) mmap(NULL, bsize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
  if (buf == MAP_FAILED) {
    LOGE("a mmap failed %s", strerror(errno));
    return 1;
  }

  *sfiles = (struct _hsv_fixed_file_arr) {.fd_buf = buf, .nr_fd = 0ULL, .max = bsize / sizeof(int), .memfd = memfd, .file_size = bsize, .flags = 0U};
  return 0;
}

int _hsv_fixed_file_arr_copy(struct _hsv_fixed_file_arr* old, struct _hsv_fixed_file_arr* new) {
  *new = *old;
  new->flags &= ~_HSV_FIXED_FILE_ARRAY_FLAG_USE_MEMFD;
  size_t len = sizeof(int) * old->max;
  new->fd_buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, old->memfd, 0);

  if (new->fd_buf == MAP_FAILED) {
    return 1;
  }

  LOGT("fd_buf = %p", (void*) new->fd_buf);
  return 0;
}

static inline int _hsv_fixed_file_arr_change_size(struct _hsv_fixed_file_arr* sfiles, size_t new_cap) {
  size_t old_len = sfiles->max * sizeof(int);
  size_t new_len = new_cap * sizeof(int);
  new_len = round_to_default_page_size(new_len);

  if (sfiles->flags & _HSV_FIXED_FILE_ARRAY_FLAG_USE_MEMFD) {
    if (ftruncate64(sfiles->memfd, new_len)) {
      LOGE("ftruncate failed: %d (%s)", errno, strerror(errno));
      return -3;
    }
  }
  void* newaddr = mremap(sfiles->fd_buf, old_len, new_len, MREMAP_MAYMOVE);
  if (UNLIKELY(newaddr == MAP_FAILED)) {
    LOGW("failed to mremap fd buffer @%p(len=%zu, new_len=%zu): %d (%s)", (void*)sfiles->fd_buf, old_len, new_cap, errno, strerror(errno));
    return -1;
  }

  sfiles->max = new_len / sizeof(int);
  sfiles->fd_buf = newaddr;

  return 0;
}

// on success returns the index (positive) negative on error
int _hsv_fixed_file_arr_add(struct _hsv_fixed_file_arr *sfiles, int fd) {
  LOGT("adding to fixed file array fd: %d", fd);
  if (UNLIKELY(sfiles->nr_fd == sfiles->max)) {
    size_t old_len = sfiles->max * sizeof(int);
    size_t new_len = (2*_theosl_utils_default_pagesize) + old_len;
    if (_hsv_fixed_file_arr_change_size(sfiles, new_len)) {
      return -3;
    }
  }

  size_t indx = sfiles->nr_fd++;
  if (UNLIKELY(indx > INT_MAX)) {
    return -2;
  }
  sfiles->fd_buf[indx] = fd;

  LOGT("added to fixed file_array fd: %d@%u", fd, indx);
  return (int)indx;
}

int _hsv_fixed_file_arr_free(struct _hsv_fixed_file_arr *sfiles) {
  if (munmap(sfiles->fd_buf, sfiles->max * sizeof(int))) {
    LOGW("failed to unmap memory leaked %s", strerror(errno));
    return 1;
  }

  return 0;
}

// uring may be NULL
int _hsv_fixed_file_arr_free_fds(struct _hsv_fixed_file_arr* sfiles) {
  int e;
  if (( e = close_range(sfiles->fd_buf[0], INT_MAX, 0) )) {
    LOGW("failed to FD after fixed file register: %d %s", errno, strerror(errno));
  }

  return e;
}

int _hsv_fixed_file_arr_reserve(struct _hsv_fixed_file_arr* sfiles, uint32_t min_cap) {
  if (min_cap <= sfiles->max) return 0;

  return _hsv_fixed_file_arr_change_size(sfiles, ((size_t) min_cap) * sizeof(int));
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

static inline void _hsv_prep_immediate_socket_close(struct hsv_engine_t *engine, struct io_uring_cqe *cqe) {
  struct io_uring_sqe* close_sqe = _hsv_io_uring_get_sqe(engine);
  io_uring_prep_close_direct(close_sqe, cqe->res);
  close_sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_CLOSE_SOCKET_IMIDIATE, cqe->res);
  close_sqe->flags |= IOSQE_CQE_SKIP_SUCCESS_BIT;
}

static inline int _hsv_ssl_enque_write(struct hsv_engine_t* engine, struct hsv_request *request, uint64_t req_id, BIO *net_bio) {
  if (request->buffers[__HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX].type != _HSV_REQUEST_BUFFER_NONE) {
    return 0;
  }
  LOGT("ssl enque write to reqid=%lu", req_id);
  char *buffer = _hsv_mbufcache_get(&engine->buf_cache, _HSV_MBUFCACHE_4K_INDX);
  const size_t bsize = 4096;
  if (!buffer) {
    buffer = mmap(NULL, bsize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);      
    if (buffer == MAP_FAILED) {
      LOGE("failed to get buffer for SSL write: %d (%s)", errno, strerror(errno));
      return 1;
    }
  }
  size_t read_request = BIO_ctrl_get_read_request(net_bio);
  BIO_read(net_bio, buffer, read_request & (bsize-1));
  struct io_uring_sqe* sqe = io_uring_get_sqe(&engine->uring);
  io_uring_prep_write(sqe, request->asock_indx, buffer, read_request, 0);
  sqe->flags |= IOSQE_FIXED_FILE;
  sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_SSL_WRITE, req_id);

  request->buffers[__HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX].type = _HSV_REQUEST_BUFFER_IOV;
  request->buffers[__HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX].data.iovec.iov_base = buffer;
  request->buffers[__HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX].data.iovec.iov_len = bsize;
  
  return 0;
}

void _hsv_post_handshake_setup(struct hsv_engine_t *engine, uint64_t reqid) {
  LOGI("HANDSHAKE DONE for reqid=%lu", reqid); 

  struct hsv_request *request = &engine->requests[reqid];
  struct io_uring_sqe *ulp_sqe = _hsv_io_uring_get_sqe(engine);
  // setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
  io_uring_prep_cmd_sock(ulp_sqe, SOCKET_URING_OP_SETSOCKOPT, request->asock_indx, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
  ulp_sqe->user_data = OP_USER_DATA(_HSV_ROP_SSL_SETSOCKOPT, reqid);
  ulp_sqe->flags |= IOSQE_FIXED_FILE;

  // struct io_uring_sqe *tx_sqe = _hsv_io_uring_get_sqe(engine);
  // io_uring_prep_cmd_sock(tx_sqe, SOCKET_URING_OP_SETSOCKOPT, request->asock_indx, SOL_TLS, TLS_TX, )
}

static inline void _hsv_ssl_close_request(struct hsv_engine_t *engine, uint64_t reqid) {
  struct io_uring_sqe *rsqe = _hsv_io_uring_get_sqe(engine);
  struct io_uring_sqe *wsqe = _hsv_io_uring_get_sqe(engine);

  uint64_t rud = CHANGE_USER_DATA_OP(_HSV_ROP_SSL_READ, reqid);
  io_uring_prep_cancel(rsqe, &rud, IORING_ASYNC_CANCEL_ALL);
  rsqe->user_data = OP_USER_DATA(_HSV_ROP_CANCEL_READ, reqid);

  uint64_t wud = CHANGE_USER_DATA_OP(_HSV_ROP_SSL_WRITE, reqid);
  io_uring_prep_cancel(wsqe, &wud, IORING_ASYNC_CANCEL_ALL);
  wsqe->user_data = OP_USER_DATA(_HSV_ROP_CANCEL_WRITE, reqid);

  _hsv_close_request(engine, reqid);
}

static inline void _hsv_do_ssl_accept(struct hsv_engine_t* engine, struct hsv_request *request, uint64_t req_id) {
  LOGT("do_ssl_accept start: reqid=%zu", req_id);
  if (UNLIKELY((request->flags & _HSV_REQUSET_FLAG_INFLIGHT) == 0)) {
    return;
  }
  struct _hsv_request_data_ssl_accept *ssl_data = &request->data.ssl_accept;
  SSL * const ssl = ssl_data->ssl;
  BIO * net_bio = ssl_data->net_bio;
  int ret = SSL_accept(ssl);
  LOGT("SSL_accept ret=%d", ret);
  if (ret == -1) {
    int e = SSL_get_error(ssl, ret);
    size_t pending = BIO_ctrl_pending(net_bio);
    if (pending > 0) {
      LOGT("SSL want to write %zu bytes", pending);
      if (_hsv_ssl_enque_write(engine, request, req_id, net_bio)) {
        return;
      }
    }
    switch (e) {
      case SSL_ERROR_WANT_READ: {
        if (request->flags & _HSV_REQUSET_FLAG_SSL_READ_INFLIGHT) {
          LOGT("ssl read in progress skipping", NULL);
          return;
        }
        struct io_uring_sqe* sqe = io_uring_get_sqe(&engine->uring);
        io_uring_prep_read(sqe, request->asock_indx, NULL, INPUT_URING_INPUT_BUF_SIZE, 0);
        sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
        sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_SSL_READ, req_id);
        sqe->buf_group = INPUT_URING_INPUT_BUF_GID;
        LOGT("SSL want read: reqid=%u", req_id);
      }
      break;

      case SSL_ERROR_WANT_WRITE: {
        LOGT("SSL want write: reqid=%u", req_id);
        if (request->buffers[__HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX].type != _HSV_REQUEST_BUFFER_NONE) {
          LOGT("write allready in progress skipping", NULL);
          return;
        }
        int e = _hsv_ssl_enque_write(engine, request, req_id, net_bio);
        if (e) {
          _hsv_ssl_close_request(engine, req_id);
          return;
        }
      }
      break;
      default:
        LOGE("unknown SSL ERROR: %d", e);
        ERR_print_errors_fp(stdout);
        _hsv_ssl_close_request(engine, req_id);
        return;
    }
  } else if (ret == 0) {
    _hsv_ssl_close_request(engine, req_id);
    return;
  } else if (ret == 1) {
    _hsv_post_handshake_setup(engine, req_id);
  }
 
}

static inline struct hsv_request* _hsv_accept_sec_request(struct hsv_engine_t *engine, uint64_t req_indx, struct io_uring_cqe *cqe) {
  struct hsv_request* request = &engine->requests[req_indx];
  *request = (struct hsv_request)
      { .flags = _HSV_REQUSET_FLAG_INFLIGHT, .asock_indx = cqe->res};

  return request;
}

void _hsv_handle_sec_accept(struct hsv_engine_t* engine, struct io_uring_cqe *cqe) {
  if (cqe->res < 0) {
    LOGE("failed to accept socket because %s", strerror(-errno));
    return;
  }

  SSL *ssl = SSL_new(engine->tls.ctx);
  if (!ssl) {
    LOGE("failed to create SSL object: ", NULL);
    ERR_print_errors_fp(stdout);

    _hsv_prep_immediate_socket_close(engine, cqe);
    return;
  }

  BIO *ssl_bio, *net_bio;
  int e = BIO_new_bio_pair(&ssl_bio, 0, &net_bio, 0);
  if (!e) {
    LOGE("failed to create bio pair: ", NULL);
    ERR_print_errors_fp(stdout);

    _hsv_prep_immediate_socket_close(engine, cqe);
    return;
  }

  SSL_set_bio(ssl, ssl_bio, ssl_bio);

  uint64_t user_data = engine->dynuser_data;
  if (_hsv_aquire_request(&user_data, engine)) {
    LOGE("failed to aquire request", NULL);
    _hsv_prep_immediate_socket_close(engine, cqe);
    return;
  }
  const uint64_t req_indx = user_data;

  struct hsv_request *request = _hsv_accept_sec_request(engine, req_indx, cqe);
  request->state = HSV_REQUEST_STATE_SSL_ACCEPT;
  request->data.ssl_accept = (struct _hsv_request_data_ssl_accept) {
    .net_bio = net_bio,
    .ssl_bio = ssl_bio,
    .ssl = ssl
  };

  LOGT("starting TLS handshake", NULL);
 
  _hsv_do_ssl_accept(engine, request, req_indx);
}


void _hsv_handle_accept(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  if (cqe->res < 0) {
    LOGE("failed to accept socket because %s", strerror(-errno));
    return;
  }

  uint64_t user_data = engine->dynuser_data; 
  if (_hsv_aquire_request(&user_data, engine)) {
    struct io_uring_sqe* send_sqe = _hsv_io_uring_get_sqe(engine);

    io_uring_prep_send(send_sqe, cqe->res, _hsv_message_too_many_connections, _hsv_message_too_many_connections_size, MSG_NOSIGNAL);
    send_sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_SEND_ERROR, user_data);
    // it is ok not to send cqe because it does not use a buffer as it's backing store
    send_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_CQE_SKIP_SUCCESS | IOSQE_IO_HARDLINK;

    _hsv_prep_immediate_socket_close(engine, cqe);
    return;
  }

  struct hsv_request* request = _hsv_accept_sec_request(engine, user_data, cqe);
  
  engine->dynuser_data = (engine->dynuser_data + 1) & (HSV_MAXIMUM_REQUEST_NR-1);
  LOGT("new dyn user data: %llu", engine->dynuser_data);

  struct io_uring_sqe* sqe = _hsv_enqueue_read(engine, request, user_data);
  LOGT("new request %lu socket: %d (readOP{user_data=%llx})",user_data, cqe->res, sqe->user_data);
}

void _hsv_dprint_requests(struct hsv_engine_t* engine) {
  LOGD("REQUESTS START", NULL);

  for (size_t i = 0; i < HSV_MAXIMUM_REQUEST_NR; ++i) {
    struct hsv_request* request = engine->requests + i;
    printf("\t%zu: flag=%u, sock=%d, file_sending={file=%d, file_offset=%ld}, buffers=[%d, %d]\n",
           i, request->flags, request->asock_indx, request->data.file_sending.file ? request->data.file_sending.file->fd : -1,
           request->data.file_sending.file_offset, request->buffers[0].type, request->buffers[1].type);
  }

  LOGD("REQUESTs END", NULL);
}

static inline void _hsv_close_conn_after_initial_read(struct hsv_engine_t *engine, const struct io_uring_cqe *cqe, size_t req_indx, char* buffer, uint16_t buf_id) {
    struct io_uring_sqe* close_sqe = io_uring_get_sqe(&engine->uring); 
    io_uring_prep_close_direct(close_sqe, cqe->res);
    close_sqe->user_data = OP_USER_DATA(_HSV_ROP_CLOSE_SOCKET, req_indx);

    _hsv_ibufring_return(engine, buffer, buf_id);
  
}

// static inline int _hsv_read_headers(char* const buffer, size_t buffer_len) {  }

static inline int _hsv_handle_static_file_server_read(
                      struct hsv_engine_t* engine, struct io_uring_cqe* cqe, const char* const path,
                      size_t path_length, enum hsv_http_request_method http_method,
                      const struct hsv_path_handler* const hander, uint16_t buf_id, char* buffer, size_t req_indx
                  ) {

  if (http_method != HSV_HTTP_METHOD_GET) {
    LOGD("static file handler http method is not get but %u", http_method);
    _hsv_close_conn_after_initial_read(engine, cqe, req_indx, buffer, buf_id);
    return 1;
  }

  const struct hsv_static_file_path *const sfh = &hander->info.ss_path_info;
  const struct hsv_file_info *const finfo = &sfh->finfo;

  /// writev better?
  static const char* const resp_start = "HTTP/1.1 %u %s\r\nContent-Type: %s; charset=utf-8\r\nContent-Length: %lu\r\n";
  unsigned response_code = 200;
  const char* const resp_msg = "OK";
  const char* const content_type = hsv_http_content_type_strings[sfh->ctype];
  int buf_len = snprintf(buffer, INPUT_URING_INPUT_BUF_SIZE, resp_start, response_code, resp_msg, content_type, sfh->finfo.file_size);

  if (sfh->cencodeing) {
    char* ptr = buffer + buf_len;
    size_t max_size = INPUT_URING_INPUT_BUF_SIZE - buf_len;
    char ceb[_hsv_content_encoding_string_max_len];
    int ceb_len = hsv_content_encoding_list_to_string(sfh->cencodeing, ceb);
    int nlen = snprintf(ptr, max_size, "Content-Encoding: %.*s\r\n", ceb_len, ceb);
    buf_len += nlen;
  }

  if (buf_len + 2 > INPUT_URING_INPUT_BUF_SIZE) {
    _hsv_close_conn_after_initial_read(engine, cqe, req_indx, buffer, buf_id);
    return 1;
  }

  *(buffer + buf_len++) = '\r';
  *(buffer + buf_len++) = '\n';

  int req_sock_fdi = engine->requests[req_indx].asock_indx;

  struct io_uring_sqe* header_sqe = io_uring_get_sqe(&engine->uring);
  struct io_uring_sqe* body_in_sqe = io_uring_get_sqe(&engine->uring);
  struct io_uring_sqe* body_out_sqe = io_uring_get_sqe(&engine->uring);

  io_uring_prep_send(header_sqe, req_sock_fdi, buffer, buf_len, MSG_NOSIGNAL);
  header_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK; // | IOSQE_CQE_SKIP_SUCCESS_BIT;
  header_sqe->user_data = OP_USER_DATA(_HSV_ROP_INITIAL_SEND, req_indx);

  int pipe_indx_out = engine->fixed_file_offset + 2 * req_indx;
  int pipe_indx_in = pipe_indx_out + 1;
  // LOGT("ffoffset=%d pipe in %d, pipe out %d", engine->fixed_file_offset, pipe_indx_in, pipe_indx_out);

  LOGT("sending file %d of size %ld", finfo->fd, finfo->file_size);
  LOGD("splicing fixed file %d to %d len=%zu", finfo->fd, pipe_indx_in, finfo->file_size);
  io_uring_prep_splice(body_in_sqe, finfo->fd, 0, pipe_indx_in, -1, finfo->file_size, SPLICE_F_FD_IN_FIXED);
  body_in_sqe->flags |= IOSQE_FIXED_FILE; // | IOSQE_CQE_SKIP_SUCCESS_BIT;
  body_in_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_IN_PIPE, req_indx);

  io_uring_prep_splice(body_out_sqe, pipe_indx_out, -1, req_sock_fdi, -1, finfo->file_size, SPLICE_F_FD_IN_FIXED);
  body_out_sqe->flags |= IOSQE_FIXED_FILE;
  body_out_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_OUT_PIPE, req_indx);
  struct hsv_request* request = &engine->requests[req_indx];
  if (_hsv_request_buffer_input_buffer_add(request, buf_id)) {
    LOGE("failed to add buffer closing socket", NULL);
    _hsv_close_request(engine, req_indx);
    return 1;
  }
  request->data.file_sending.file = finfo;
  request->data.file_sending.file_offset = 0;

  // LOGT("using the file with fixed fd=%d of length %zu", entry->data.fd, entry->data.file_size);
  // LOGT("sent file ffindx=%d of size %zu to %d", entry->data.fd, entry->data.file_size, req_sock_fdi);
 return 0; 
}

static inline int _hsv_handle_raw_static_file_server_read (
                      struct hsv_engine_t* engine, struct io_uring_cqe* cqe, const char* const path,
                      size_t path_length, enum hsv_http_request_method http_method,
                      const struct hsv_path_handler* const hander, uint16_t buf_id, char* buffer, size_t req_indx
                  ) {
  if (!(hander->info.raw_ss_path_info.flags & HSV_RAW_STATIC_FILE_PATH_FLAG_NO_HTTP_METHOD_CHECK)) {
    if (http_method != HSV_HTTP_METHOD_GET) {
      LOGD("static file handler http method is not get but %u", http_method);
      _hsv_close_conn_after_initial_read(engine, cqe, req_indx, buffer, buf_id);
      return 1;
    }
  }

  const struct hsv_raw_static_file_path *const sfh = &hander->info.raw_ss_path_info;
  const struct hsv_file_info *const finfo = &sfh->finfo;

  int req_sock_fdi = engine->requests[req_indx].asock_indx;

  struct io_uring_sqe* body_in_sqe = io_uring_get_sqe(&engine->uring);
  struct io_uring_sqe* body_out_sqe = io_uring_get_sqe(&engine->uring);


  int pipe_indx_out = engine->fixed_file_offset + 2 * req_indx;
  int pipe_indx_in = pipe_indx_out + 1;

  LOGT("raw sending file %d of size %ld", finfo->fd, finfo->file_size);
  LOGD("splicing fixed file %d to %d len=%ld", finfo->fd, pipe_indx_in, finfo->file_size);
  io_uring_prep_splice(body_in_sqe, finfo->fd, 0, pipe_indx_in, -1, finfo->file_size, SPLICE_F_FD_IN_FIXED);
  body_in_sqe->flags |= IOSQE_FIXED_FILE;
  body_in_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_IN_PIPE, req_indx);

  io_uring_prep_splice(body_out_sqe, pipe_indx_out, -1, req_sock_fdi, -1, finfo->file_size, SPLICE_F_FD_IN_FIXED);
  body_out_sqe->flags |= IOSQE_FIXED_FILE;
  body_out_sqe->user_data = OP_USER_DATA(_HSV_ROP_SEND_FILE_OUT_PIPE, req_indx);
  struct hsv_request* request = &engine->requests[req_indx];
  request->data.file_sending.file = finfo;
  request->data.file_sending.file_offset = 0;

  _hsv_ibufring_return(engine, buffer, buf_id);
 return 0; 
}

/// This is probbalbly not portable but works on my mechine :)
enum hsv_http_request_method _hsv_scan_request_method(char* buffer, uint_fast8_t* path_start_off) {
  uint64_t req_method_full; // = *(uint64_t*)buffer; // buffer is char* and is page aligned so this is fine
  memcpy(&req_method_full, buffer, sizeof(uint64_t));
  uint64_t req_method3 = req_method_full & 0xffffffff;
  uint64_t req_method4 = req_method_full & 0xffffffffff;
  uint64_t req_method5 = req_method_full & 0xffffffffffff;
  uint64_t req_method6 = req_method_full & 0xffffffffffffff;
  uint64_t req_method7 = req_method_full & UINT64_MAX;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
#pragma GCC diagnostic ignored "-Wpedantic"
  *path_start_off = 4;
  switch (req_method3) {
    case ' TEG':
      return HSV_HTTP_METHOD_GET;
    case ' TUP':
      return HSV_HTTP_METHOD_PUT;
  }

  *path_start_off = 5;
  switch (req_method4) {
    case ' DAEH':
      return HSV_HTTP_METHOD_HEAD;
    case ' TSOP':
      return HSV_HTTP_METHOD_POST;
  }

  *path_start_off = 6;
  switch (req_method5) {
    case ' ECART':
      return HSV_HTTP_METHOD_TRACE;
    case ' HCTAP':
      return HSV_HTTP_METHOD_PATCH;
  }

  *path_start_off = 7;
  switch (req_method6) {
    case ' ETELED':
      return HSV_HTTP_METHOD_DELETE;
  }

  *path_start_off = 8;
  switch (req_method7) {
    case ' TCENNOC':
      return HSV_HTTP_METHOD_CONNECT;
    case ' SNOITPO':
      return HSV_HTTP_METHOD_OPTIONS;
  }

#pragma GCC diagnostic pop

  return _HSV_HTTP_METHOD_LAST;
}


void _hsv_handle_read(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
    LOGE("the CQE shoud use a buffer: %s; \tcqe{res=%d, ud=%llx}", strerror(-cqe->res), cqe->res, cqe->user_data);
    exit(1);
  }

  size_t req_indx = GET_DYN_USER_DATA(cqe->user_data);
  uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  LOGT("reading request %lu (res=%d, bufid=%u, cqe_flags=%x, ud=%llx)", req_indx, cqe->res, buf_id, cqe->flags, cqe->user_data);
  char* buffer = (char*)engine->buf_ring_backing + buf_id * INPUT_URING_INPUT_BUF_SIZE; 

  if (cqe->res == -EPIPE || cqe->res == 0) {
    _hsv_ibufring_return(engine, buffer, buf_id);
    LOGT("closing request %llu", req_indx);
   _hsv_close_request(engine, req_indx);
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

  uint_fast8_t path_start_off;
  enum hsv_http_request_method http_method = _hsv_scan_request_method(buffer, &path_start_off);
  if (http_method == _HSV_HTTP_METHOD_LAST) {
    LOGD("UNKNOWN HTTP METHOD %.8s", buffer);
    _hsv_close_conn_after_initial_read(engine, cqe, req_indx, buffer, buf_id);
    return;
  }

  char* path_start = buffer + path_start_off;
  char* ptr = path_start;
  while (*(ptr) != ' ') { ptr++; }

  static const char http_version_string[] = "HTTP/1.1\r\n";

  size_t path_len = ptr - path_start;

  if (memcmp(++ptr, http_version_string, sizeof(http_version_string) -1)) {
    _hsv_close_conn_after_initial_read(engine, cqe, req_indx, buffer, buf_id);
    LOGD("invalid http version", NULL);
    return;
  }

  struct map_hsv_path_handler_t* hmap = &engine->path_map;
  struct map_hsv_path_handler_entry* mhentry = map_hsv_path_handler_get(hmap, path_start, path_len);

  const struct hsv_path_handler* handler;

  if (mhentry == NULL) {
    LOGD("using default handler for %.*s", (int)path_len, path_start);
    handler = &engine->default_handler;  
  } else {
    handler = &mhentry->data;   
  }

  int e;
  switch (handler->htype) {
    case HSV_HANDLER_STATIC_FILE:
      e = _hsv_handle_static_file_server_read(engine, cqe, path_start, path_len, http_method, handler, buf_id, buffer, req_indx);
    break;
    case HSV_HANDLER_STATIC_FILE_RAW:
      e = _hsv_handle_raw_static_file_server_read(engine, cqe, path_start, path_len, http_method, handler, buf_id, buffer, req_indx);
    break;
    case HSV_HANDLER_EXTERNAL_HANDLER:
    case HSV_HANDLER_REDIRECT:
    default:
      e = -1;
    break;
  }

  if (e) {
    LOGE("HANDLER ERROR", NULL);
  }
}


void _hsv_handle_socket_close_cqe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe) {
  uint64_t req_indx = GET_DYN_USER_DATA(cqe->user_data);
  LOGD("closed socket of request=%lu", req_indx);
  struct hsv_request* request = &engine->requests[req_indx];

  if (cqe->res < 0) {
    LOGE("failed to close socket of %llu (user_data=0x%llx) is closed: res=%d flags=%x", GET_DYN_USER_DATA(cqe->user_data), cqe->user_data, cqe->res, cqe->flags);
  }

  _hsv_free_request_buffers(engine, request);
  request->flags = 0U;
  request->state = HSV_REQUEST_STATE_UNINITIALIZED;
}


void _hsv_close_request(struct hsv_engine_t* engine, uint64_t request_index) {
  struct io_uring_sqe* cs_sqe;
  cs_sqe = _hsv_io_uring_get_sqe(engine);

  struct hsv_request* request = &engine->requests[request_index];
  // _hsv_free_request_buffers(engine, request);
  io_uring_prep_close_direct(cs_sqe, request->asock_indx);
  io_uring_sqe_set_data64(cs_sqe, OP_USER_DATA(_HSV_ROP_CLOSE_SOCKET, request_index));

  request->flags &= ~_HSV_REQUSET_FLAG_INFLIGHT;

  LOGT("closing socket %d of %u", request->asock_indx, request_index);
}

void _hsv_ibufring_return(struct hsv_engine_t* engine, char* buffer, uint16_t buf_id) {
  const int mask = io_uring_buf_ring_mask(INPUT_URING_INPUT_BUF_NR);
  io_uring_buf_ring_add(engine->input_buffer_ring, buffer, INPUT_URING_INPUT_BUF_SIZE, buf_id, mask, engine->input_buffer_buf_offset++);
}

// int _hsv_ss_key_buffer_init(struct hsv_engine_t* engine) {
//   char* key_buf = mmap(NULL, _HSV_SS_KEY_BUFFER_INITIAL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | _HSV_SS_KEY_BUFFER_INITIAL_MMAP_HPAGE_FLAGS, -1, 0);
//   if (key_buf == MAP_FAILED) {
//     return 1;
//   }

//   LOGT("key buffer start at %p ends at %p", key_buf, key_buf + _HSV_SS_KEY_BUFFER_INITIAL_SIZE);
//   engine->static_server.key_buf = key_buf;
//   engine->static_server.key_buf_next = key_buf;
//   engine->static_server.key_buf_size = _HSV_SS_KEY_BUFFER_INITIAL_SIZE;  

//   return 0;
// }

// int _hsv_ss_key_buffer_free(struct hsv_engine_t* engine) {
//   int r;
//   if ((r = munmap(engine->static_server.key_buf, engine->static_server.key_buf_size))) {
//     LOGW("memory leak failed to munmap static_server.key_buffer: %s", strerror(errno));
//   }
//   return r;
// }

struct io_uring_sqe* _hsv_enqueue_read(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx) {
  struct io_uring_sqe* sqe = io_uring_get_sqe(&engine->uring);
  io_uring_prep_read(sqe, request->asock_indx, NULL, INPUT_URING_INPUT_BUF_SIZE, 0);
  sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
  sqe->user_data = CHANGE_USER_DATA_OP(_HSV_ROP_READ, req_indx);
  sqe->buf_group = INPUT_URING_INPUT_BUF_GID;

  return sqe;
}

struct io_uring_sqe* _hsv_io_uring_get_sqe(struct hsv_engine_t* engine) {
  return __hsv_io_uring_get_sqe(&engine->uring);
}

struct io_uring_sqe* __hsv_io_uring_get_sqe(struct io_uring* uring) {
  struct io_uring_sqe* sqe;

  while (!(sqe = io_uring_get_sqe(uring))) {
    __HSV_IO_URING_SUBMIT(uring);
  }

  return sqe;
}

int _hsv_request_buffer_add(struct hsv_request *request, const struct _hsv_request_buffer *const buffer) {
  const size_t arrlen = sizeof(request->buffers) / sizeof(request->buffers[0]);
  size_t i = 0;
  for (; i < arrlen; ++i) {
    if (request->buffers[i].type == _HSV_REQUEST_BUFFER_NONE) {
      request->buffers[i] = *buffer;

      return 0;
    }
  }

  return 1;
}

int _hsv_request_buffer_input_buffer_add(struct hsv_request *request, int indx) {
  auto buffer = (struct _hsv_request_buffer){.type = _HSV_REQUEST_BUFFER_INPUT_BUFFER_OFFSET, .data.input_indx = indx};
  return _hsv_request_buffer_add(request, &buffer);  
}

int _hsv_request_buffer_iov_add(struct hsv_request *request, void* iov_base, size_t iov_len) {
  auto buffer = (struct _hsv_request_buffer){
    .type = _HSV_REQUEST_BUFFER_INPUT_BUFFER_OFFSET,
    .data.iovec = (struct iovec){.iov_base = iov_base, .iov_len = iov_len}
  };
  return _hsv_request_buffer_add(request, &buffer);  
}

void _hsv_free_request_buffers(struct hsv_engine_t* engine, struct hsv_request* request) {
  const size_t arrlen = sizeof(request->buffers) / sizeof(request->buffers[0]);
  for (uint_fast16_t i = 0; i < arrlen; ++i) {
    switch (request->buffers[i].type) {
      case _HSV_REQUEST_BUFFER_NONE:
      break;
      case _HSV_REQUEST_BUFFER_INPUT_BUFFER_OFFSET:
        int buf_id = request->buffers[i].data.input_indx;
        void* buf_ptr = engine->buf_ring_backing + buf_id * INPUT_URING_INPUT_BUF_SIZE;
        _hsv_ibufring_return(engine, buf_ptr, buf_id);
      break;   

      case _HSV_REQUEST_BUFFER_IOV: {
        struct iovec *iovec = &request->buffers[i].data.iovec;
        if (!(iovec->iov_len & (_theosl_utils_default_pagesize-1)) && !((size_t)iovec->iov_base & (_theosl_utils_default_pagesize-1))) {
          if (-1 == munmap(iovec->iov_base, iovec->iov_len)) {
            LOGW("failed to munmap iov request buffer: %d (%s)", errno, strerror(errno));
          }
        }
      }
    }

    request->buffers[i].type = _HSV_REQUEST_BUFFER_NONE;
  }
}

void _hsv_handle_ssl_read(struct hsv_engine_t* engine, struct io_uring_cqe *cqe) {
  uint64_t reqid = GET_DYN_USER_DATA(cqe->user_data);

  LOGT("handle ssl read reqid=%zu, res=%d", reqid, cqe->res);

  if (cqe->res == 0 || cqe->res == -EPIPE) {
    LOGD("connection closed by remote: %d of %lu", engine->requests[reqid].asock_indx, reqid);
    _hsv_ssl_close_request(engine, reqid);
    return;
  }
  if (cqe->res < 0) {
    LOGE("read from %d failed: %d (%s)", engine->requests[reqid].asock_indx, -cqe->res, strerror(-cqe->res));
    _hsv_ssl_close_request(engine, reqid);
    return;
  }

  size_t req_indx = GET_DYN_USER_DATA(cqe->user_data);
  uint16_t buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  char* buffer = (char*)engine->buf_ring_backing + buf_id * INPUT_URING_INPUT_BUF_SIZE; 

  struct hsv_request * request = &engine->requests[reqid];

  if (UNLIKELY((request->flags & _HSV_REQUSET_FLAG_INFLIGHT) == 0)) {
    _hsv_ibufring_return(engine, buffer, buf_id);
    return;
  }
  
  BIO *net_bio = request->data.ssl_accept.net_bio;
  SSL *ssl = request->data.ssl_accept.ssl;
  size_t written = 0;
  bio_write:
  int e = BIO_write_ex(net_bio, buffer + written, cqe->res - written, &written);
  LOGT("BIO_write: e=%d\twriten=%zu of=%d", e, written, cqe->res);
  if (!e && !BIO_should_retry(net_bio)) {
    LOGE("failed to write to net_bio: %d", e);
    ERR_print_errors_fp(stdout);
    _hsv_ssl_close_request(engine, req_indx);
    return;
  }
  if (written != cqe->res) {
    /*
      WARN
      THIS is a bit risque coz if ssl want read here and
      it did not consume enough of the bio the bio might be full and thus written == 0 
      TODO
      Doing this correctly is quite a bit complicated because now I need to preserve this buffer and do a write
      then when the write finishes do SSL_accept then try to give it this buffer again the best way to do this
      would probably be to create fixed indexes into request buffers where one is a write buffer from bufcache and
      one is a read buffer from input_buf_ring because at any one time only one read and one write buffer exists
    */
    SSL_accept(ssl);
    goto bio_write;
  }

  request->flags &= ~_HSV_REQUSET_FLAG_SSL_READ_INFLIGHT;
  _hsv_ibufring_return(engine, buffer, buf_id);

  _hsv_do_ssl_accept(engine, request, reqid);
}

void _hsv_handle_ssl_write(struct hsv_engine_t* engine, struct io_uring_cqe *cqe) {
  uint64_t reqid = GET_DYN_USER_DATA(cqe->user_data);

  LOGT("handle ssl write reqid=%zu", reqid);

  if (cqe->res < 0) {
    LOGE("write to %d failed: %d (%s)", engine->requests[reqid].asock_indx, -cqe->res, strerror(-cqe->res));
    _hsv_close_request(engine, reqid);
    return;
  }

  struct hsv_request *request = &engine->requests[reqid];
  struct _hsv_request_buffer *buffer = &request->buffers[__HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX];
  buffer->type = _HSV_REQUEST_BUFFER_NONE;
  int e = _hsv_mbufcache_give(&engine->buf_cache, _HSV_MBUFCACHE_4K_INDX, buffer->data.iovec.iov_base);
  if (e) {
    e = munmap(buffer->data.iovec.iov_base, buffer->data.iovec.iov_len);
    if (e) {
      LOGW("failed to munmap buffer: %d (%s)", errno, strerror(errno));
    }
  }
  
  _hsv_do_ssl_accept(engine, request, reqid);
}

int _hsv_setup_ktls(struct hsv_engine_t *engine, uint64_t reqid, struct hsv_request *request) {


  return 0;
}

void _hsv_handle_ssl_setsockopt(struct hsv_engine_t *engine, struct io_uring_cqe *cqe) {
  const uint64_t reqid = GET_DYN_USER_DATA(cqe->user_data);
  struct hsv_request *request = &engine->requests[reqid];

  if (cqe->res < 0) {
    LOGE("failed to set TLS ULP on socket req=%lu, sock_indx=%u", reqid, request->asock_indx);
    _hsv_close_request(engine, reqid);
    return;
  }

  // _hsv_setup_ktls()
}
