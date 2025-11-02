#include "hserv.h"
#include <netinet/in.h>
#include <stdlib.h>

#include <theosl/log.h>
#include <theosl/vec.h>
#include <theosl/ss.h>


int main(int argc, char** argv) {
 
  struct hsv_params params;
  uint16_t port = 8080, sport = 4443;

  int e = 0;
  if ((e = hsv_params_init_default_ip(&params, port, sport))) {
    LOGE("failed to init hsv_params: %d", e);
    return 1;
  }

  params.static_server.pipe_size = (1ULL << 21);

  for (int i = 1; i < argc; ++i) {
    LOGT("arg %d: ```%s```", i, argv[i]);
    if ((argv[i][0] == '-') && (argv[i][1] == '-')) {
      if (!strcmp("port", argv[i]+2)) {
        if (!sscanf(argv[++i], "%hu", &params.port)) {
          LOGE("failed to read port number: %d", errno);
          return 1;
        }
        continue;
      }
      if (!strcmp("sport", argv[i]+2)) {
        if (!sscanf(argv[++i], "%hu", &params.sport)) {
          LOGE("failed to read sport number: %d", errno);
          return 1;
        }
        continue;
      }

      LOGE("unknown flag `%s`", argv[i]);
      return 1;
    }

    char* sep_ptr = argv[i];
    while ((*(sep_ptr) != ':')) {
      if (*sep_ptr == '\0') {
        LOGE("invalid static file mapping: ```%s```", argv[i]);
        return 1;
      }
      ++sep_ptr;
    }
    *sep_ptr = '\0';

    struct hsv_block_handler bh;
    bh.htype = HSV_HANDLER_STATIC_FILE;
    bh.sfile.flags = 0;
    bh.sfile.src_dir = argv[i];  

    hsv_params_add_block(&params, sep_ptr+1, &bh);
  }


  LOGI("starting server on ports: (%u, %u)", params.port, params.sport);
  struct hsv_engine_t engine;
  if ((e = hsv_init(&engine, &params))) {
    LOGE("HSV INIT ERROR %d", e);
    exit(1);
  }

  if ( (e = hsv_serve(&engine))) {
    LOGE("HSV SERVE ERROR %d", e);
    exit(1);
  }
}


