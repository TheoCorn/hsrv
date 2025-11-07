#include <unistd.h>
#include "attributes.h"

const char _hsv_message_too_many_connections[] HSV_WEAK_SYMBOL _HSV_PUBLIC_ABI =
    "HTTP/1.1 503 Service Unavailable\n"
    "Content-Type: text/html;\n"
    "Content-Length: 406\n"
    "\n"
    "<!doctype html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "  <title>503 Service Unavailable</title>\n"
    "</head>\n"
    "<body>\n"
    "  <h1>503 Service Unavailable</h1>\n"
    "  <p>The server was unable to complete your request. Please try again later.</p>\n"
    "  <p>If this problem persists, please <a href=\"https://example.com/support\">contact support</a>.</p>\n"
    "  <p>Server logs contain details of this error with request ID: ABC-123.</p>\n"
    "</body>\n"
    "</html>\n"
    ;

const size_t _hsv_message_too_many_connections_size HSV_WEAK_SYMBOL _HSV_PUBLIC_ABI = sizeof(_hsv_message_too_many_connections)-1;

const char _hsv_message_default_response[] _HSV_PUBLIC_ABI =
    "HTTP/1.1 404 NOT FOUND\r\n"
    "Content-Type: text/html;\r\n"
    "Content-Length: 176\r\n"
    "\r\n"
    "<!doctype html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "  <title>404 NOT FOUND</title>\n"
    "</head>\n"
    "<body>\n"
    "  <h1>404 NOT FOUND</h1>\n"
    "  <p>The requested resource does not exist.</p>\n"
    "</body>\n"
    "</html>\n"
    ;

const size_t _hsv_message_default_response_size _HSV_PUBLIC_ABI = sizeof(_hsv_message_default_response)-1;
