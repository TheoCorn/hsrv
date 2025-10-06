
## A bit of wierdness in the architecture
Because I initially wanted to make a more general http server not just a static
file server, I used buf ring. For the use of a static file server a request should realy only take up
a fraction if the single buffer size and any larger request should be responded with `431 Request Header Fields Too Large`.
They are GET requests and should not have content.

So a more efficient buffer scheme is possible.

Currently all the buffers to be used are preallocated before the start of the uring.
