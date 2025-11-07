#include "http_headers.h"
#include <string.h>

const char* const hsv_http_content_type_strings[] = {
  "text/html",
  "text/plain",
  "text/javascript",
  "text/css",
  "application/json",
  "text/markdown",
  "application/x-tar",
  "image/ico",
  "image/jpeg",
  "image/raw",
  "image/png",
  "image/svg+xml",
  "image/gif",
  "application/pdf",
  "text/csv",
  "audio/mp3",
  "video/mp4",
  "video/mpeg",
  "font/otf",
  "font/ttf",
};

const char* const hsv_http_content_encoding_strings[] = {
  "gzip", "compress", "deflate", "br", "zstd", "dcb", "dcz"
};

size_t _hsv_content_encoding_string_max_len = sizeof("gzip, compress, deflate, br, zstd, dcb, dcz");

const char*const hsv_http_request_method_strings[] = {
  "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
};

int hsv_content_encoding_list_to_string(hsv_content_encoding_list_t encodings, char *restrict buffer) {
  char* next = buffer;
  enum hsv_content_encoding_id cencoding;
  while (((cencoding = (encodings & 0xffff)))) {
    encodings >>= 8;
    next = stpcpy(next, hsv_http_content_encoding_strings[cencoding-1]);
    *(next++) = ',';
    *(next++) = ' ';
  }

  return next - buffer;
}
