#include <stdint.h>
#include <stddef.h>

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
  HTTP_CONTENT_TYPE_ID_ICO,
  HTTP_CONTENT_TYPE_ID_JPEG,
  HTTP_CONTENT_TYPE_ID_RAW,
  HTTP_CONTENT_TYPE_ID_PNG,
  HTTP_CONTENT_TYPE_ID_SVG,
  HTTP_CONTENT_TYPE_ID_GIF,
  HTTP_CONTENT_TYPE_ID_PDF,
  HTTP_CONTENT_TYPE_ID_CSV,
  HTTP_CONTENT_TYPE_ID_MP3,
  HTTP_CONTENT_TYPE_ID_MP4,
  HTTP_CONTENT_TYPE_ID_MPEG,
  HTTP_CONTENT_TYPE_ID_OTF,
  HTTP_CONTENT_TYPE_ID_TTF,

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

extern size_t _hsv_content_encoding_string_max_len;

inline int hsv_content_encoding_list_add(hsv_content_encoding_list_t* cel, enum hsv_content_encoding_id etype) {
  if (*cel & (0xffULL << 56)) {
    return 1;
  }

  *cel <<= sizeof(enum hsv_content_encoding_id);
  *cel += etype;

  return 0;
}

extern const char* const hsv_http_content_encoding_strings[];

int hsv_content_encoding_list_to_string(hsv_content_encoding_list_t encodings, char *restrict buffer);

#endif
