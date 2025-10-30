#include <stdint.h>

#ifndef HTTP_HEADERS_H
#define HTTP_HEADERS_H

enum hsv_content_type_id : uint8_t {
  HTTP_CONTENT_TYPE_ID_HTML = 0U,
  HTTP_CONTENT_TYPE_ID_PLAIN,
  HTTP_CONTENT_TYPE_ID_JAVASCRIPT,
  HTTP_CONTENT_TYPE_ID_CSS,
  HTTP_CONTENT_TYPE_ID_JSON,
  HTTP_CONTENT_TYPE_ID_MARKDOWN,
  HTTP_CONTENT_TYPE_ID_TAR,
};

extern const char* const hsv_http_content_type_strings[];

enum hsv_content_encoding_id : uint8_t {
  HTTP_CONTENT_ENCODING_ID_NONE = 0U,
  HTTP_CONTENT_ENCODING_ID_GZIP,
  HTTP_CONTENT_ENCODING_ID_COMPRESS,
  HTTP_CONTENT_ENCODING_ID_DEFLATE,
  HTTP_CONTENT_ENCODING_ID_BROTLI,
  HTTP_CONTENT_ENCODING_ID_ZSTD,
  HTTP_CONTENT_ENCODING_ID_DCB,
  HTTP_CONTENT_ENCODING_ID_DCZ
};

typedef uint64_t hsv_content_encoding_list_t;

inline int hsv_content_encoding_list_add(hsv_content_encoding_list_t* cel, enum hsv_content_encoding_id etype) {
  if (*cel & (0xffULL << 56)) {
    return 1;
  }

  *cel <<= sizeof(enum hsv_content_encoding_id);
  *cel += etype;

  return 0;
}

extern const char* const hsv_http_content_encoding_strings[];


#endif
