#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <theosl/ss.h>

inline static void logt(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...);
inline static void logd(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...);
inline static void logi(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...);
inline static void logw(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...);
inline static void loge(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...);

#ifndef THEOSL_LOGGING
#define THEOSL_LOGGING
enum LOG_LEVEL {
  LOG_TRACE=0,
  LOG_DEBUG,
  LOG_INFO,
  LOG_WARN,
  LOG_ERROR,
};

// for a bit faster loggin but can set log level and output, 
// allways prints
#define PRINTT(format, ...) printf("\x1b[1m\x1b[35m[ TRACE " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define PRINTD(format, ...) printf("\x1b[1m\x1b[34m[ DEBUG " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __func__, __LINE__, __VA_ARGS__)
#define PRINTI(format, ...) printf("\x1b[1m\x1b[32m[ INFO " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define PRINTW(format, ...) printf("\x1b[1m\x1b[33m[ WARN " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define PRINTE(format, ...) printf("\x1b[1m\x1b[31m[ ERROR " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)

// a bit slower but more features
#ifndef THEOSL_NO_LOG

#ifndef THOSL_NO_LOGT
#define LOGT(format, ...) logt(format, __FILE__, __func__, __LINE__, __VA_ARGS__)
#else
#define LOGT(format, ...) 
#endif

#ifndef THOSL_NO_LOGD
#define LOGD(format, ...) printf("\x1b[1m\x1b[34m[ DEBUG " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __func__, __LINE__, __VA_ARGS__)
#else
#define LOGD(format, ...) 
#endif

#ifndef THEOSL_NO_LOGI
#define LOGI(format, ...) printf("\x1b[1m\x1b[32m[ INFO " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define LOGI(format, ...)
#endif

#ifndef THEOSL_NO_LOGW
#define LOGW(format, ...) printf("\x1b[1m\x1b[33m[ WARN " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define LOGW(format, ...)
#endif

#ifndef THEOSL_NO_LOGE
#define LOGE(format, ...) printf("\x1b[1m\x1b[31m[ ERROR " __FILE__ ":%s" ":%d" " ]\x1b[0m " format "\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#else
#define LOGE(format, ...)
#endif

#else
  #define LOGT(format, ...)
  #define LOGD(format, ...)
  #define LOGI(format, ...)
  #define LOGW(format, ...)
  #define LOGE(format, ...)
#endif

void logt(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...) {
  va_list args;
  va_start(args, line);
  uint8_t buffer[4096];
  int e = sprintf((char*)buffer, "\x1b[1m\x1b[35m[ TRACE %s:%s:%d ]\x1b[0m %s \n", file, function, line, format);
  assert(e > 0);
  vprintf((char*)buffer, args);
  va_end(args);
}
void logd(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...) {
  va_list args;
  va_start(args, line);
  uint8_t buffer[4096];
  int e = sprintf((char*)buffer, "\x1b[1m\x1b[34m[ DEBUG %s:%s:%d ]\x1b[0m %s \n", file, function, line, format);
  assert(e > 0);
  vprintf((char*)buffer, args);
  va_end(args);
}
void logi(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...) {
  va_list args;
  va_start(args, line);
  uint8_t buffer[4096];
  int e = sprintf((char*)buffer, "\x1b[1m\x1b[32m[ INFO %s:%s:%d ]\x1b[0m %s \n", file, function, line, format);
  assert(e > 0);
  vprintf((char*)buffer, args);
  va_end(args);
}
void logw(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...) {
  va_list args;
  va_start(args, line);
  uint8_t buffer[4096];
  int e = sprintf((char*)buffer, "\x1b[1m\x1b[33m[ WARN %s:%s:%d ]\x1b[0m %s \n", file, function, line, format);
  assert(e > 0);
  vprintf((char*)buffer, args);
  va_end(args);
}
void loge(const char* __restrict format, const char* __restrict file, const char* __restrict function, const int line, ...) {
  va_list args;
  va_start(args, line);
  uint8_t buffer[4096];
  int e = sprintf((char*)buffer, "\x1b[1m\x1b[31m[ ERROR %s:%s:%d ]\x1b[0m %s \n", file, function, line, format);
  assert(e > 0);
  vprintf((char*)buffer, args);
  va_end(args);
}

#endif
