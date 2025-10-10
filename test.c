#include "hserv.h"
#include <netinet/in.h>
#include <stdlib.h>

#include <theosl/log.h>

int main(int argc, char** argv) {
  char* dir = "./test";

  struct hsv_params params = (struct hsv_params) {
    .address4 = INADDR_ANY,
    .address6 = in6addr_any,
    .port = 3000,
    .static_server = {.dirs = &dir, .nr_dirs = 1, .pipe_size = (int)(1ULL << 21)}
  };

  struct hsv_engine_t engine;
  int e;
  if ((e = hsv_init(&engine, &params))) {
    LOGE("HSV INIT ERROR %d", e);
    exit(1);
  }

  if ( (e = hsv_serve(&engine))) {
    LOGE("HSV SERVE ERROR %d", e);
    exit(1);
  }
}


