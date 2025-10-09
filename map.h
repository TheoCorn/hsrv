#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#ifndef _MAP_H
#define _MAP_H

inline uint64_t _map_hash_fun(const char *key, size_t key_len);

#define Map(data_t) struct map##data_t##_t

#define MAP_DEF(data_t)                                                        \
  struct map##data_t##_entry {                                                           \
    uint64_t hash;                                                             \
    const char *key;                                                           \
    size_t key_len;                                                            \
    struct map##data_t##_entry *next;                                                    \
                                                                               \
    struct data_t data;                                                        \
  };                                                                           \
                                                                               \
struct map##data_t##_t {\
  size_t arr_size;\
  size_t arr_mask;\
  struct map##data_t##_entry *arr;\
  struct map##data_t##_entry *aux_arr;\
  size_t aux_len;\
  size_t aux_size;\
};\
\
int map##data_t##_init(struct map##data_t##_t *m, uint32_t expected_entry); \
bool key##data_t##_matches(struct map##data_t##_entry *entry, const char *key, size_t key_len, uint64_t hash); \
struct map##data_t##_entry *map##data_t##_get(struct map##data_t##_t *m, const char *key, size_t key_len); \
int map##data_t##_set(struct map##data_t##_t *m, const char *key, size_t key_len, struct data_t *data); \
typedef int (*map_iin_data_aquire_fun)(struct data_t *, const char *, size_t, void *);\
int map##data_t##_insert_if_not_exists(struct map##data_t##_t *m, const char *key, size_t key_len, map_iin_data_aquire_fun daf, void *daf_arg);


#define MAP_IMPL(data_t) \
int map##data_t##_init(struct map##data_t##_t *m, uint32_t expected_entry) {\
  size_t arr_size;\
  size_t arr_mask;\
  {\
    arr_size = 2 * expected_entry;\
    int lz = __builtin_clzl(arr_size);\
    arr_mask = SIZE_MAX >> (lz);\
    arr_size = arr_mask + 1;\
  }\
  LOGT("setting map main array size to %zu", arr_size); \
\
  m->arr_size = arr_size;\
  m->arr_mask = arr_mask;\
  m->arr = (struct map##data_t##_entry *)mmap(\
      NULL, arr_size * sizeof(struct map##data_t##_entry), PROT_READ | PROT_WRITE,\
      MAP_ANONYMOUS | MAP_SHARED | MAP_HUGETLB, -1, 0ULL);\
  if (m->arr == MAP_FAILED)\
    return -1;\
  LOGT("file map array at %p", m->arr);\
\
  m->aux_size = expected_entry;\
  m->aux_len = 0ULL;\
  m->aux_arr = (struct map##data_t##_entry *)mmap(\
      NULL, m->aux_size * sizeof(struct map##data_t##_entry), PROT_READ | PROT_WRITE,\
      MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0ULL);\
  if (m->aux_arr == MAP_FAILED) {\
    return -2;\
  }\
\
  return 0;\
}\
\
bool key##data_t##_matches(struct map##data_t##_entry *entry, const char *key, size_t key_len,\
                 uint64_t hash) {\
  return (key_len == entry->key_len && hash == entry->hash &&\
          !strncmp(key, entry->key, key_len));\
}\
\
struct map##data_t##_entry *map##data_t##_get(struct map##data_t##_t *m, const char *key, size_t key_len) {\
  uint64_t hash = _map_hash_fun(key, key_len);\
  uint64_t indx = hash & m->arr_mask;\
  /* LOGT("looking for %.*s (len=%zu, hash=%llu)", (int)key_len, key, key_len, hash); */ \
\
  struct map##data_t##_entry *entry = &m->arr[indx];\
  /* LOGT("root entry %llu (%p)", indx, entry); */ \
\
  do {\
    /* LOGT("checking entry at %p {key:(%p) %.*s , key_len: %zu}", entry, entry->key, entry->key, entry->key_len); */ \
    if (key##data_t##_matches(entry, key, key_len, hash)) {\
      return entry;\
    }\
  } while ((entry = entry->next));\
\
  return NULL;\
}\
\
int map##data_t##_set(struct map##data_t##_t *m, const char *key, size_t key_len,\
            struct data_t *data) {\
  uint64_t hash = _map_hash_fun(key, key_len);\
  uint64_t indx = hash & m->arr_mask;\
\
  struct map##data_t##_entry *entry = &m->arr[indx];\
\
  if (entry->key) {\
    if (m->aux_len == m->aux_size)\
      return -1;\
    while (entry->next) {\
      entry = entry->next;\
    }\
\
    entry->next = m->aux_arr + m->aux_len++;\
    entry = entry->next;\
  }\
\
  entry->hash = hash;\
  entry->key = key;\
  entry->key_len = key_len;\
  entry->data = *data;\
\
  return 0;\
}\
\
int map##data_t##_insert_if_not_exists(struct map##data_t##_t *m, const char *key, size_t key_len,\
                             map_iin_data_aquire_fun daf, void *daf_arg) {\
  uint64_t hash = _map_hash_fun(key, key_len);\
  uint64_t indx = hash & m->arr_mask;\
\
  struct map##data_t##_entry *entry = &m->arr[indx];\
\
  if (entry->key) {\
    do {\
      if (key##data_t##_matches(entry, key, key_len, hash)) {\
        return 0;\
      }\
\
      entry = entry->next;\
    } while (entry->next);\
\
    if (m->aux_len == m->aux_size) return -1;\
    entry->next = m->aux_arr + m->aux_len++;\
    entry = entry->next;\
  }\
\
  int daf_res = daf(&entry->data, key, key_len, daf_arg);\
  if (daf_res) return daf_res;\
\
  entry->hash = hash;\
  entry->key = key;\
  entry->key_len = key_len;\
  entry->next = NULL; \
  LOGT("inserted %.*s (key_ptr=%p, key_len=%zu, hash=%llu) at %p", (int)key_len, key, entry->key, key_len, hash, entry); \
\
  return 0;\
}

#endif
