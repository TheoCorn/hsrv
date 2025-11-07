#include "_hserv.h"
#include <theosl/utils/align.h>

// static int _hsv_deal_with_file(int fd, const char *path, char *path_end,
//                                struct _hsv_dents_buffers *dents_buffer,
//                                struct hsv_engine_t *engine,
//                                struct _hsv_fixed_file_arr *sf) {
//   struct stat64 fs;
//   if (fstat64(fd, &fs)) {
//     return 1;
//   }

//   int e;
//   switch (fs.st_mode & S_IFMT) {
//   case __S_IFDIR:
//     e = _hsv_read_dir(fd, path, path_end, dents_buffer, engine, sf);
//     break;
//   case __S_IFREG: {
//     e = _hsv_ss_insert_file(fd, fs.st_size, path, path_end, engine, sf);
//   } break;
//   default:
//     LOGW("file load (%s: inode=%lu): unservable file type", path, fs.st_ino);
//     return 2;
//     break;
//   }

//   return e;
// }

// int _hsv_read_dir(int dir_fd, const char *path, char *path_end,
//                   struct _hsv_dents_buffers *dbs, struct hsv_engine_t
//                   *engine, struct _hsv_fixed_file_arr *sf) {
//   LOGT("reading dir %s\n", path);
//   void *db;
//   if (!(db = _hsv_dents_get(dbs))) {
//     LOGE("failed to accquire a dents buffer skipping direcotory %s", path);
//     return 1;
//   }
//   ssize_t dlen;
//   while ((
//       dlen = getdents64(dir_fd, db,
//       _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE))) {
//     if (dlen == -1) {
//       LOGE("error getdents64 %s", strerror(errno));
//       return -2;
//     }

//     int e = 0;
//     ssize_t offt = 0;
//     while (offt < dlen) {
//       struct linux_dirent64 *de = (struct linux_dirent64 *)(db + offt);
//       LOGD("processing file: %s/%s", path, de->d_name);
//       switch (de->d_type) {
//       case DT_REG: {
//         int fd = openat(dir_fd, de->d_name, O_RDONLY);
//         if (fd == -1) {
//           LOGE("error opening %s/%s (e: %s) skipping", path, de->d_name,
//                strerror(errno));
//           break;
//         }

//         struct stat64 fs;
//         if (fstat64(fd, &fs)) {
//           LOGE("error fstating %s/%s %s skipping", path, de->d_name,
//                strerror(errno));
//           break;
//         }

//         char *new_end = _hsv_add_to_path(path, path_end, de->d_name);
//         e = _hsv_ss_insert_file(fd, fs.st_size, path, new_end, engine, sf);
//         if (e) {
//           LOGE("error inserting file %d skipping", e);
//           break;
//         }

//         *path_end = '\0';
//       } break;
//       case DT_DIR: {
//         // if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
//         if (_hsv_read_dir_should_ingnore_file(de->d_name)) {
//           LOGT("throwing out %s/%s", path, de->d_name);
//           e = 0;
//           break;
//         }
//         LOGT("reading dir %s", de->d_name);
//         int fd = openat(dir_fd, de->d_name, O_RDONLY | O_DIRECTORY);
//         if (fd == -1) {
//           LOGE("error opening directory fd %s skipping", strerror(errno));
//           e = -1;
//           break;
//         }
//         char *end = _hsv_add_to_path(path, path_end, de->d_name);
//         e = _hsv_read_dir(fd, path, end, dbs, engine, sf);
//         *path_end = '\0';
//         if (e) {
//           return e;
//         }
//       } break;
//       case DT_LNK: {
//         LOGT("dt link %s", de->d_name);
//         int fd = openat(dir_fd, de->d_name, O_RDONLY);
//         if (fd < 0) {
//           LOGE("error openning %s/%s %s", path, de->d_name, strerror(errno));
//           break;
//         }
//         char *end = _hsv_add_to_path(path, path_end, de->d_name);
//         e = _hsv_deal_with_file(fd, path, end, dbs, engine, sf);
//         *path_end = '\0';
//       } break;
//       case DT_UNKNOWN: {
//         LOGT("DT unknown %s", de->d_name);
//         int fd = openat(dir_fd, de->d_name, O_RDONLY);
//         char *end = _hsv_add_to_path(path, path_end, de->d_name);
//         e = _hsv_deal_with_file(fd, path, end, dbs, engine, sf);
//         *path_end = '\0';
//       } break;
//       default:
//         break;
//       }

//       if (e) {
//         LOGW("SKIPPING some files due to errors (%d)", e);
//       }

//       offt += de->d_reclen;
//     }
//   }

//   _hsv_dents_free_buffer(dbs);

//   return 0;
// }

void *_hsv_dents_get(struct _hsv_dents_buffers *db) {
  if (db->len == db->cap) {
    size_t old_len = db->cap * sizeof(void *);
    size_t new_len = old_len + _theosl_utils_default_pagesize;
    void *addr = mremap(db->buffers, old_len, new_len, MREMAP_MAYMOVE);
    if (addr == MAP_FAILED) {
      LOGE("failed to realloc dents array: %d (%s)", errno, strerror(errno));
      return NULL;
    }
    db->buffers = addr;
    db->cap = new_len / sizeof(void *);
  }

  void **place = &db->buffers[db->len];
  if (!*place) {
    *place = mmap(NULL, _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE,
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS |
                      _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS,
                  -1, 0);
    if (*place == MAP_FAILED) {
      LOGE("it is very likely a mmap failed because you have not enabled "
           "hugepages: %s",
           strerror(errno));
      *place = NULL;
      return NULL;
    }
  }
  db->len++;

  return *place;
}

int _hsv_dents_buffers_init(struct _hsv_dents_buffers *db) {
  db->cap = _theosl_utils_default_pagesize / sizeof(void *);
  db->buffers =
      mmap(NULL, _theosl_utils_default_pagesize, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (MAP_FAILED == db->buffers) {
    return 1;
  }
  void *dents_buffer = mmap(
      NULL, 3 * _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS |
          _HSV_STATIC_FILE_READ_DENTS_BUFFER_MMAP_HPAGE_FLAGS,
      -1, 0);
  if (dents_buffer == MAP_FAILED) {
    LOGE("it is very likely a mmap failed because you have not enabled "
         "hugepages: %s",
         strerror(errno));
    return 1;
  }
  db->buffers[0] = dents_buffer;
  db->buffers[1] = dents_buffer + _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE;
  db->buffers[2] = dents_buffer + 2 * _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE;

  db->len = 0;

  return 0;
}

void _hsv_dents_free_buffer(struct _hsv_dents_buffers *db) { db->len -= 1; }

void _hsv_dents_free_buffers(struct _hsv_dents_buffers *db) {
  for (size_t i = 0; i < db->cap; ++i) {
    if (!db->buffers[i]) {
      return;
    }

    if (munmap(db->buffers[i], _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE)) {
      LOGW("memory leak: faild to munmap memmory (%s) at %p of expected size "
           "%llu",
           strerror(errno), db->buffers[i],
           _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE);
    }
  }
}

void _hsv_dents_free(struct _hsv_dents_buffers *db) {
  _hsv_dents_free_buffers(db);
  if (munmap(db->buffers, db->cap * sizeof(void *))) {
    LOGW("failed to unmap dents buffer array: %d (%s)", errno, strerror(errno));
  }
}

// dname must be located at a address that can be read up to dname + 2
int _hsv_read_dir_should_ingnore_file(char *dname) {
  static const uint32_t this = '.' << 2 * sizeof(char);
  static const uint32_t super = (('.' << sizeof(char)) + '.') << sizeof(char);
  uint32_t name =
      ((((*dname) << sizeof(char)) + *(dname + 1)) << sizeof(char)) +
      *(dname + 2);

  return this == name || super == name;
}

char *_hsv_add_to_path(const char *path, char *path_end, char *fname) {
  *path_end = '/';
  char *end = stpcpy(path_end + 1, fname);

  return end;
}

// int _hsv_load_files(struct hsv_params *params, struct hsv_engine_t *engine,
//                     struct _hsv_fixed_file_arr *sf) {
//   struct _hsv_dents_buffers dents_buffers;
//   int e;
//   if ((e = _hsv_dents_buffers_init(&dents_buffers))) {
//     return 1;
//   }

//   char *path_buf =
//       mmap(NULL, HSV_STATIC_PATH_BUFFER_SIZE, PROT_READ | PROT_WRITE,
//            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

//   for (size_t i = 0; i < params->static_server.nr_dirs; ++i) {
//     char *ipath = params->static_server.dirs[i];
//     char *end = stpcpy(path_buf, *ipath == '.' ? ipath + 1 : ipath);
//     int fd = open(ipath, O_RDONLY);
//     if (fd == -1) {
//       LOGE("failed to open root directory %s",
//       params->static_server.dirs[i]); return 1;
//     }
//     int e;
//     if ((e = _hsv_deal_with_file(fd, path_buf, end, &dents_buffers, engine,
//                                  sf))) {
//       LOGE("problem with %s (%d)", path_buf, e);
//     }
//   }

//   _hsv_dents_free_buffers(&dents_buffers);
//   // TODO check for errors on unmaps
//   if (munmap(path_buf, HSV_STATIC_PATH_BUFFER_SIZE)) {
//     LOGW("failed to deallocate path buffer: %s", strerror(errno));
//   }
//   return 0;
// }

int _hsv_read_dir_in_params(struct hsv_params *params, int dir_fd,
                            const char *path, char *path_end,
                            struct _hsv_dents_buffers *dbs);
int _hsv_ss_insert_file_in_params(struct hsv_params *params, int fd,
                                  size_t file_size, const char *path,
                                  const char *path_end);

int _hsv_deal_with_file_in_params(struct hsv_params *params, int fd,
                                  const char *path, char *path_end,
                                  struct _hsv_dents_buffers *dents_buffer) {
  struct stat64 fs;
  if (fstat64(fd, &fs)) {
    return 1;
  }

  int e;
  switch (fs.st_mode & S_IFMT) {
  case __S_IFDIR:
    e = _hsv_read_dir_in_params(params, fd, path, path_end, dents_buffer);
    break;
  case __S_IFREG: {
    e = _hsv_ss_insert_file_in_params(params, fd, fs.st_size, path, path_end);
  } break;
  default:
    LOGW("file load (%s: inode=%lu): unservable file type", path, fs.st_ino);
    return 2;
    break;
  }

  return e;
}

int _hsv_read_dir_in_params(struct hsv_params *params, int dir_fd,
                            const char *path, char *path_end,
                            struct _hsv_dents_buffers *dbs) {
  LOGT("reading dir %s\n", path);
  void *db;
  if (!(db = _hsv_dents_get(dbs))) {
    LOGE("failed to accquire a dents buffer skipping direcotory %s", path);
    return 1;
  }
  ssize_t dlen;
  while ((
      dlen = getdents64(dir_fd, db, _HSV_STATIC_FILE_READ_DENTS_BUFFER_SIZE))) {
    if (dlen == -1) {
      LOGE("error getdents64 %s", strerror(errno));
      return -2;
    }

    int e = 0;
    ssize_t offt = 0;
    while (offt < dlen) {
      struct linux_dirent64 *de = (struct linux_dirent64 *)(db + offt);
      LOGD("processing file: %s/%s", path, de->d_name);
      switch (de->d_type) {
      case DT_REG: {
        int fd = openat(dir_fd, de->d_name, O_RDONLY);
        if (fd == -1) {
          LOGE("error opening %s/%s (e: %s) skipping", path, de->d_name,
               strerror(errno));
          break;
        }

        struct stat64 fs;
        if (fstat64(fd, &fs)) {
          LOGE("error fstating %s/%s %s skipping", path, de->d_name,
               strerror(errno));
          break;
        }

        char *new_end = _hsv_add_to_path(path, path_end, de->d_name);
        e = _hsv_ss_insert_file_in_params(params, fd, fs.st_size, path,
                                          new_end);
        if (e) {
          LOGE("error inserting file %d skipping", e);
          break;
        }

        *path_end = '\0';
      } break;
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
        char *end = _hsv_add_to_path(path, path_end, de->d_name);
        e = _hsv_read_dir_in_params(params, fd, path, end, dbs);
        *path_end = '\0';
        if (e) {
          return e;
        }
      } break;
      case DT_LNK: {
        LOGT("dt link %s", de->d_name);
        int fd = openat(dir_fd, de->d_name, O_RDONLY);
        if (fd < 0) {
          LOGE("error openning %s/%s %s", path, de->d_name, strerror(errno));
          break;
        }
        char *end = _hsv_add_to_path(path, path_end, de->d_name);
        e = _hsv_deal_with_file_in_params(params, fd, path, end, dbs);
        *path_end = '\0';
      } break;
      case DT_UNKNOWN: {
        LOGT("DT unknown %s", de->d_name);
        int fd = openat(dir_fd, de->d_name, O_RDONLY);
        char *end = _hsv_add_to_path(path, path_end, de->d_name);
        e = _hsv_deal_with_file_in_params(params, fd, path, end, dbs);
        *path_end = '\0';
      } break;
      default:
        break;
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

int _hsv_load_files_in_params(struct hsv_params *params, const char *const root,
                              const char *const mount,
                              struct hsv_block_handler *handler) {
  assert(handler->htype == HSV_HANDLER_STATIC_FILE);

  struct _hsv_dents_buffers dents_buffers;
  int e;
  if ((e = _hsv_dents_buffers_init(&dents_buffers))) {
    return 1;
  }

  char *path_buf =
      mmap(NULL, HSV_STATIC_PATH_BUFFER_SIZE, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  char *end = stpcpy(path_buf, mount);
  int fd = open(root, O_RDONLY);
  if (fd == -1) {
    LOGE("failed to open root directory %s", root);
    return 1;
  }
  if ((e = _hsv_deal_with_file_in_params(params, fd, path_buf, end,
                                         &dents_buffers))) {
    LOGE("problem with %s (%d)", path_buf, e);
  }

  _hsv_dents_free_buffers(&dents_buffers);

  return 0;
}

/// does not support utf-8 which is ok because extensions are ascii
// static uint64_t mchchlit_to_lower_case(uint64_t str) __attribute((pure));
// static uint64_t mchchlit_to_upper_case(uint64_t str) __attribute((pure));
// static uint64_t mchchlit_to_lower_case(uint64_t str) {
//   uint64_t b = 0;
//   while (str) {
//     b <<= 8;
//     uint64_t ch = str & 0xff;
//     if (ch >= 'A' && ch <= 'Z') {
//       ch += 0x20;
//     }
//     b += ch;

//     str >>= 8;
//   }
//   return b;
// }
// static uint64_t mchchlit_to_upper_case(uint64_t str) {
//   uint64_t b = 0;
//   while (str) {
//     b <<= 8;
//     uint64_t ch = str & 0xff;
//     if (ch >= 'a' && ch <= 'z') {
//       ch -= 0x20;
//     }
//     b += ch;

//     str >>= 8;
//   }

//   return b;
// }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define _HSV_MULTI_CHAR_CHAR_CONST(str) str
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#warn big endian code is untested
#define _HSV_MULTI_CHAR_CHAR_CONST(str) __builtin_bswap64(str)
#else
#error __BYTE_ORDER__ is neither big nor little endian
#endif
#define SET_CONTENT_TYPE(type)                                                 \
  ((!ctype_set) ? ({                                                           \
    LOGD("content_type: " #type " file=%s", path);                             \
    *ctype = type;                                                             \
    ctype_set = true;                                                          \
  })                                                                           \
                : false)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
#pragma GCC diagnostic ignored "-Wpedantic"

int _hsv_get_file_content_te(struct hsv_params *params, int fd,
                             size_t file_size, const char *path,
                             const char *path_end,
                             enum hsv_content_type_id *ctype,
                             hsv_content_encoding_list_t *et_list) {

  const char *last_end = path_end - 1;
  const char *ext_start = path_end;

  *ctype = HTTP_CONTENT_TYPE_ID_PLAIN;
  *et_list = (hsv_content_encoding_list_t)HTTP_CONTENT_ENCODING_ID_NONE;

read_fext:
  while (*--ext_start != '.') {
    if (*ext_start == '/') {
      return 0;
    }
  }
  ++ext_start;

  // const _hsv_uint64_unaligned *ext_ptr = (_hsv_uint64_unaligned *)ext_start;
  // uint64_t mask = UINT64_MAX;
  size_t len = last_end - ext_start + 1;
  // LOGT("extension_len=%zu, ext_start=%p, last_end=%p", len, ext_start,
  // last_end);

  // no extension is longer then 8 bytes
  if (len > sizeof(uint64_t)) {
    goto unknown_extension;
  }

  // mask >>= sizeof(uint64_t) - len;
  // uint64_t data = *ext_ptr & mask;
  // LOGT("extension %.*s(0x%lx)", (int)len, ext_start, data);
  bool ctype_set = false;
  // switch (data) {
  //   case _HSV_MULTI_CHAR_CHAR_CONST('html'):
  //     SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_HTML);
  //     break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('txt'):
  //     SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_PLAIN);
  //     break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('js'):
  //     SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_JAVASCRIPT);
  //     break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('css'):
  //     SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_CSS);
  //     break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('md'):
  //   case _HSV_MULTI_CHAR_CHAR_CONST('MD'):
  //     SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_MARKDOWN);
  //     break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('tar'):
  //     SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_TAR);
  //     break;
  // }

  switch (len) {
  case 2:
    if (!strncasecmp(ext_start, "js", 2)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_JAVASCRIPT);
    } else if (!strncasecmp(ext_start, "md", 2)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_MARKDOWN);
    }
    break;
  case 3:
    if (!strncasecmp(ext_start, "txt", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_PLAIN);
    } else if (!strncasecmp(ext_start, "css", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_CSS);
    } else if (!strncasecmp(ext_start, "tar", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_TAR);
    } else if (!strncasecmp(ext_start, "tgz", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_TAR);
      hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_GZIP);
    } else if (!strncmp(ext_start, "ico", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_ICO);
    } else if (!strncasecmp(ext_start, "png", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_PNG);
    } else if (!strncasecmp(ext_start, "raw", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_PNG);
    } else if (!strncasecmp(ext_start, "jpg", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_JPEG);
    } else if (!strncasecmp(ext_start, "gif", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_GIF);
    } else if (!strncasecmp(ext_start, "svg", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_SVG);
    } else if (!strncasecmp(ext_start, "pdf", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_PDF);
    } else if (!strncasecmp(ext_start, "csv", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_CSV);
    } else if (!strncasecmp(ext_start, "mp3", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_MP3);
    } else if (!strncasecmp(ext_start, "mp4", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_MP4);
    } else if (!strncmp(ext_start, "otf", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_OTF);
    } else if (!strncmp(ext_start, "ttf", 3)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_TTF);
    }
    break;
  case 4:
    if (!strncasecmp(ext_start, "html", 4)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_HTML);
    } else if (!strncasecmp(ext_start, "json", 4)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_JSON);
    } else if (!strncasecmp(ext_start, "jpeg", 4)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_JPEG);
    } else if (!strncasecmp(ext_start, "mpeg", 4)) {
      SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_MPEG);
    }
    break;
  }

  if (ctype_set) {
    return 0;
  }

  switch (len) {
  case 2:
    if (!strncasecmp(ext_start, "gz", 2)) {
      hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_GZIP);
    } else if (!strncasecmp(ext_start, "br", 2)) {
      hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_BROTLI);
    } else
      goto unknown_extension;
    break;
  case 3:
    if (!strncasecmp(ext_start, "zst", 3)) {
      hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_ZSTD);
    } else
      goto unknown_extension;
    break;
  case 4:
    if (!strncasecmp(ext_start, "gzip", 4)) {
      hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_GZIP);
    } else
      goto unknown_extension;
    break;
  unknown_extension:
  default:
    LOGW("unknown extension %.*s", (int)len, ext_start);
  }

  // switch (data) {
  //   case _HSV_MULTI_CHAR_CHAR_CONST('tgz'):
  //   SET_CONTENT_TYPE(HTTP_CONTENT_TYPE_ID_TAR);
  //   case _HSV_MULTI_CHAR_CHAR_CONST('gzip'):
  //   case _HSV_MULTI_CHAR_CHAR_CONST('gz'):
  //     hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_GZIP);
  //   break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('br'):
  //     hsv_content_encoding_list_add(et_list,
  //     HTTP_CONTENT_ENCODING_ID_BROTLI);
  //   break;
  //   case _HSV_MULTI_CHAR_CHAR_CONST('zst'):
  //     hsv_content_encoding_list_add(et_list, HTTP_CONTENT_ENCODING_ID_ZSTD);
  //   break;
  //   unknown_extension:
  //   default:
  //     LOGW("unknown extension %.*s", (int)len, ext_start);
  // }

  last_end = ext_start - 2;
  ext_start = last_end;
  goto read_fext;
}
#pragma GCC diagnostic pop

int _hsv_ss_insert_file_in_params(struct hsv_params *params, int fd,
                                  size_t file_size, const char *path,
                                  const char *path_end) {
  int e = 0;
  int indx = _hsv_fixed_file_arr_add(&params->ffile_arr, fd);
  if (indx < 0) {
    return -1;
  }

  // if (_hsv_params_pbuf_add(params, path, path_length)) {
  //   return 1;
  // }

  struct hsv_path_handler handler = (struct hsv_path_handler){
      .flags = 0,
      .htype = HSV_HANDLER_STATIC_FILE,
      .info.ss_path_info =
          (struct hsv_static_file_path){.finfo = (struct hsv_file_info){
                                            .file_size = file_size,
                                            .fd = indx,
                                        }}};

  struct hsv_static_file_path *ssp_info = &handler.info.ss_path_info;
  e = _hsv_get_file_content_te(params, fd, file_size, path, path_end,
                               &ssp_info->ctype, &ssp_info->cencodeing);
  if (e) {
    LOGW("file content encoding and type error %d", e);
  }

  // handler.info.ss_path_info.finfo = (struct hsv_file_info){.fd = indx,
  // .file_size = file_size};

  size_t path_length = path_end - path;
  if ((e = _hsv_params_path_add(params, path, path_length, &handler))) {
    LOGE("_hsv_params_path_add failed: %d", e);
    return 1;
  }

  LOGT("registered fd: %d@%u at path %s", fd, indx, path);

  return 0;
}
