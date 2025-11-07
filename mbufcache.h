#include <stddef.h>
#include <stdint.h>

#define _HSV_MBUFCACHE_NR_SIZES 1

enum _hsv_mbufcache_buffer_sizes : uint8_t {
 _HSV_MBUFCACHE_4K_INDX = 0,
};

struct __hsv_mbufcache_bufs {
  void** buffers;
  size_t cap;
  size_t len;
};

struct _hsv_mbufcache {
  struct __hsv_mbufcache_bufs bcaches[_HSV_MBUFCACHE_NR_SIZES];
};

void* _hsv_mbufcache_get(struct _hsv_mbufcache* mbc, enum _hsv_mbufcache_buffer_sizes size);
int _hsv_mbufcache_give(struct _hsv_mbufcache* mbc, enum _hsv_mbufcache_buffer_sizes size, void* buffer);
int _hsv_mbufcache_init(struct _hsv_mbufcache *mbc, size_t *caps);

