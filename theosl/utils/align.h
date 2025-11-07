#ifndef _THSOSL_UTILS_ALIGN_H
#define _THSOSL_UTILS_ALIGN_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "../log.h"

size_t _theosl_utils_default_pagesize __attribute((weak));
void _theosl_utils_get_page_size() __attribute((weak, constructor));
void _theosl_utils_get_page_size() {
  int s = sysconf(_SC_PAGESIZE);
  if (s == -1) {
    LOGE("sysconf(_SC_PAGESIZE) failed: %d (%s)", errno, strerror(errno));
    exit(1);
  }

  _theosl_utils_default_pagesize = (size_t) s;
}


inline size_t round_to_page_size(size_t page_size, size_t len) {
  size_t page_mask = page_size-1;

  return (len + page_mask) & ~page_mask;
}

inline size_t round_to_default_page_size(size_t len) {
  return round_to_page_size(_theosl_utils_default_pagesize, len);
}


#endif
