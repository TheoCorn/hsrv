#include "_hserv.h"
#include <theosl/utils/align.h>

// inline int _hsv_params_path_add(struct hsv_params* const params, const char* const path, const size_tconst struct hsv_path_handler* const handler);
int hsv_params_init(struct hsv_params* params) {
  params->sport = 0;
  params->port = 0;
  params->address4.s_addr = INADDR_ANY;
  params->address6 = in6addr_any;

  params->block_paths = NULL;
  params->block_handler = NULL;
  params->blocks_arr_size = 0;
  params->blocks_nr = 0;

  params->paths_nr = 0;
  params->path_handlers = NULL;
  params->paths_off_cap = 0;
  params->paths_off = NULL;

  params->static_server.pipe_size =(int)(1ULL << 13);

  int e;
  if (( e = _hsv_fixed_file_arr_init(&params->ffile_arr) )) {
    LOGW("failed to init fixed file array: %d", e);
    return 1;
  }

  if (( e = _hsv_params_pbuf_init(params, _HSV_SMALL_HUGEMAP_MMAP_SIZE, _HSV_SMALL_HUGEMAP_MMAP_SIZE) )) {
    LOGW("failed to init path buffer: %d", e);
    return 2;
  }
  
  return 0;
}

void hsv_params_dprint(struct hsv_params* params) {
  LOGI("(hsv_params){port=%u, sport=%u, paths_nr=%u, paths=[", params->port, params->sport, params->paths_nr);
  for (uint32_t i = 0; i < params->paths_nr; ++i) {
    struct hsv_path_handler *handler = &params->path_handlers[i];
    uint32_t off = params->paths_off[i];
    printf("p_off=%u(%s),handler: {flags: %u, htype: %u, ", off, params->_pbuf+off, handler->flags, handler->htype);
    switch (handler->htype) {
      case HSV_HANDLER_STATIC_FILE: {
        struct hsv_static_server_path *ssp = &handler->info.ss_path_info;
        printf("ctype=%u, cencoding=%lu, finfo={fd=%d, file_size=%ld}}\n", ssp->ctype, ssp->cencodeing, ssp->finfo.fd, ssp->finfo.file_size);
      }
      break;
      case HSV_HANDLER_EXTERNAL_HANDLER:
      case HSV_HANDLER_REDIRECT:
      break;
    }
  }
  printf("]}\n");
}

int hsv_params_init_net(struct hsv_params* params, struct in_addr addr4, struct in6_addr addr6, uint16_t port, uint16_t sport) {
  hsv_params_init(params);

  params->sport = sport;
  params->port = port;
  params->address4 = addr4;
  params->address6 = addr6;

  return 0;
}

int hsv_params_init_default_ip(struct hsv_params* params, uint16_t port, uint16_t sport) {
  struct in_addr ip4;
  ip4.s_addr = INADDR_ANY;

  return hsv_params_init_net(params, ip4, in6addr_any, port, sport);
}

int hsv_params_add_path(struct hsv_params* params, const char* const path, struct hsv_path_handler* handler) {
  size_t plen = strlen(path)+1;
  return _hsv_params_path_add(params, path, plen, handler);  
}

// int _hsv_params_load_files_into_gmap() {
  
// }

inline int _hsv_params_add_sf_block(struct hsv_params* params, const char* const path, struct hsv_block_handler* handler) {
  uint32_t flags = handler->sfile.flags;
  if (flags & HSV_STATIC_SERVER_BLOCK_FLAG_USE_PATH_TREE) {
    return 1;
  } else {
    return _hsv_load_files_in_params(params, handler->sfile.src_dir, path, handler); 
  }
}

int hsv_params_add_block(struct hsv_params* params, const char* const path, struct hsv_block_handler* handler) {
  switch (handler->htype) {
    case HSV_HANDLER_STATIC_FILE:
      _hsv_params_add_sf_block(params, path, handler);
    break;
    case HSV_HANDLER_REDIRECT:
    case HSV_HANDLER_EXTERNAL_HANDLER:
      LOGW("unimplemented handlers", NULL);
    break;
    default:
      LOGW("Unknown block type %u; ignoring block", handler->htype);
  }

  return 0;
}

int _hsv_params_pbuf_init(struct hsv_params* params, size_t initial_size, size_t extend_by) {
  size_t size = round_to_default_page_size(initial_size);

  char* buf = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  if (buf == MAP_FAILED) {
    return 1;
  }

  params->_pbuf = buf;
  params->_pbuf_extend_by = extend_by ? extend_by : _theosl_utils_default_pagesize;
  params->_pbuf_size = size;
  params->_pbuf_next_off = 0ULL;

  return 0;
}

int64_t _hsv_params_pbuf_add(struct hsv_params* params, const char* const path, size_t path_length) {
  size_t min_size = params->_pbuf_next_off + path_length;
  if (params->_pbuf_size < min_size) {
    size_t new_size = params->_pbuf_size + params->_pbuf_extend_by;
    // this should never happen (paths should be less then _SC_PAGESIZE) but not checking would cause a sigsegv
    if (new_size < min_size) {
      new_size = round_to_default_page_size(min_size);
    }
    if (mremap(params->_pbuf, params->_pbuf_size, new_size, 0)) {
      LOGE("falid to remap hsv_params._pbuf without moving: %d (%s)", errno, strerror(errno));
      return -1;
    }
  }

  char *dest = params->_pbuf + params->_pbuf_next_off;
  stpncpy(dest, path, path_length);
  int64_t ret = params->_pbuf_next_off; 
  params->_pbuf_next_off += path_length + 1;

  LOGT("inserting: %.*s @ %p;len=%zu", (int)path_length, dest, dest, params->_pbuf_next_off - ret);

  return ret;
}

inline int _hsv_params_pbuf_free(struct hsv_params* params) {
  return munmap(params->_pbuf, params->_pbuf_size);
}

int _hsv_params_paths_init(struct hsv_params* const params) {
  size_t handler_buf_size = _HSV_SMALL_HUGEMAP_MMAP_SIZE;
  params->path_handlers_cap = handler_buf_size / sizeof(struct hsv_path_handler);

  size_t poff_buf_size = params->path_handlers_cap * sizeof(*params->paths_off);
  poff_buf_size = round_to_page_size(_theosl_utils_default_pagesize, poff_buf_size);

  params->paths_off_cap = poff_buf_size / sizeof(*params->paths_off);

  params->paths_off = mmap(NULL, poff_buf_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  if (MAP_FAILED == params->paths_off) {
    LOGE("failed to allocate paths_off buffer of size=%zu", poff_buf_size);
    return 1;
  }
  params->path_handlers = mmap(NULL, handler_buf_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | _HSV_SMALL_HUGEMAP_MMAP_FLAGS, -1, 0);
  if (MAP_FAILED == params->path_handlers) {
    LOGE("failed to allocate paths_off buffer of size=%zu", poff_buf_size);
    return 1;
  }

  params->paths_nr = 0U;

  return 0;
}

inline int _hsv_params_handler_add(struct hsv_params* const params, const struct hsv_path_handler* const handler) {
  if (params->paths_nr == params->path_handlers_cap) {
    size_t old_len = params->path_handlers_cap * sizeof(struct hsv_path_handler);
    void* new_addr = mremap(params->path_handlers, old_len, old_len + _HSV_SMALL_HUGEMAP_MMAP_SIZE, MREMAP_MAYMOVE);
    if (MAP_FAILED == new_addr) {
      return 1;
    }

    params->path_handlers = (struct hsv_path_handler*) new_addr;
  }

  params->path_handlers[params->paths_nr] = *handler;

  return 0;
}

inline int _hsv_params_paths_off_add(struct hsv_params *params, const uint32_t pbuf_off) {
  if (params->paths_nr == params->paths_off_cap) {
    size_t old_len = params->paths_off_cap * sizeof(*params->paths_off);
    uint32_t *new_addr = mremap(params->paths_off, old_len, old_len + _theosl_utils_default_pagesize, MREMAP_MAYMOVE);
    if (MAP_FAILED == new_addr) {
      return 1;
    }
  }

  params->paths_off[params->paths_nr] = pbuf_off;
  return 0;  
}

inline int _hsv_params_path_add(struct hsv_params* const params, const char* const path, size_t path_length, const struct hsv_path_handler* const handler) {
  int e;
  if (UNLIKELY(params->paths_nr == 0)) {
    if (( e = _hsv_params_paths_init(params) )) {
      return 1;
    }
  }

  int pbuf_off;
  // size_t path_length = strlen(path);
  const uint32_t pbuf_safe = params->_pbuf_next_off;
  if (( pbuf_off = _hsv_params_pbuf_add(params, path, path_length) ) < 0) {
    return 2;
  }

  // uint32_t new_path_nr = params->paths_nr+1;
  if (( e = _hsv_params_paths_off_add(params, pbuf_off) )) {
    params->_pbuf_next_off = pbuf_safe;
    return 3;
  }

  if (( e = _hsv_params_handler_add(params, handler) )) {
    params->_pbuf_next_off = pbuf_safe;
    return 4;
  }

  params->paths_nr += 1;

  return 0;
}
