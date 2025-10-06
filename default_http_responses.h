#ifndef _DEFAULT_HTTP_RESPONSES_H
#define _DEFAULT_HTTP_RESPONSES_H

const char _hsv_message_too_many_connections[] =
    "HTTP/1.1 503 Service Unavailable\n"
    "Content-Type: text/html;\n"
    "Content-Length: 123\n"
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

#endif
