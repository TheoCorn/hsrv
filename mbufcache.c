#include "mbufcache.h"
#include <sys/mman.h>
#include <theosl/ss.h>

void* _hsv_mbufcache_get(struct _hsv_mbufcache* mbc, enum _hsv_mbufcache_buffer_sizes size) {
  struct __hsv_mbufcache_bufs *bufs = &mbc->bcaches[size];
  if (!bufs->len) {
    return NULL;
  }

  return bufs->buffers[--bufs->len];
}

int _hsv_mbufcache_give(struct _hsv_mbufcache* mbc, enum _hsv_mbufcache_buffer_sizes size, void* buffer) {
  struct __hsv_mbufcache_bufs *bufs = &mbc->bcaches[size];
  if (UNLIKELY(bufs->len == bufs->cap)) {
    return -1;
  }

  bufs->buffers[bufs->len++] = buffer;
  return 0;
}

int _hsv_mbufcache_init(struct _hsv_mbufcache *mbc, size_t *caps) {
  size_t cap = 0;
  for (int i = 0; i < _HSV_MBUFCACHE_NR_SIZES; ++i) {
    cap += caps[i];
  }

  size_t size = cap * sizeof(void*);
  void* addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (MAP_FAILED == addr) {
    return 1;
  }

  for (int i = 0; i < _HSV_MBUFCACHE_NR_SIZES; ++i) {
    struct __hsv_mbufcache_bufs *bufs = &mbc->bcaches[i];
    bufs->cap = caps[i];
    bufs->len = 0;
    bufs->buffers = addr;
    addr += caps[i] + sizeof(void*);
  }

  return 0;
}

