#include <stdint.h>

#ifndef HTTP_HEADERS_H
#define HTTP_HEADERS_H

enum content_type_id : uint8_t {
  HTTP_CONTENT_TYPE_ID_HTML = 0,
  HTTP_CONTENT_TYPE_ID_PLAIN,
  HTTP_CONTENT_TYPE_ID_JAVASCRIPT,
  HTTP_CONTENT_TYPE_ID_CSS,
  HTTP_CONTENT_TYPE_ID_JSON,
  HTTP_CONTENT_TYPE_ID_MARKDOWN
};

extern const char* const http_content_type_strings[];

enum content_encoding_id : uint8_t {
  HTTP_CONTENT_ENCODING_ID_GZIP = 0,
  HTTP_CONTENT_ENCODING_ID_COMPRESS,
  HTTP_CONTENT_ENCODING_ID_DEFLATE,
  HTTP_CONTENT_ENCODING_ID_BROTLI,
  HTTP_CONTENT_ENCODING_ID_ZSTD,
  HTTP_CONTENT_ENCODING_ID_DCB,
  HTTP_CONTENT_ENCODING_ID_DCZ
};

extern const char* const http_content_encoding_strings[];

#endif
