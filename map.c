#include "map.h"

uint64_t _map_hash_fun(const char *key, size_t key_len) {
  const char *end = key + key_len;
  uint64_t hash = 5381;
  for (const char *p = key; p < end; ++p) {
    hash = ((hash << 5) + hash) + *p;
  }

  return hash;
}


