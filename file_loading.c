#include "_hserv.h"

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

// dname must be located at a address that can be read up to dname + 2
int _hsv_read_dir_should_ingnore_file(char* dname) {
  static const uint32_t this = '.' << 2 * sizeof(char);
  static const uint32_t super = (('.' << sizeof(char)) + '.') << sizeof(char);
  uint32_t name = ((((*dname) << sizeof(char)) + *(dname+1)) << sizeof(char)) + *(dname+2);

  return this == name || super == name;
}

char* _hsv_add_to_path(const char* path, char* path_end, char* fname) {
  *path_end = '/';
  char* end = stpcpy(path_end+1, fname);

  return end;
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
