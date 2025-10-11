# What is it
Hserv is a embedable high performance HTTP/1.1 static file server built with io uring and is thus Linux only. 
It currently only supports the x86_64 architecture.

# Getting up and running
## Building from source
There is a dependency on `liburing`. So you might need to `sudo apt install liburing liburing-dev` on debian based systems or `sudo dnf install liburing liburing-devel` on REHL based systems.
Other than that just `make`.

## Setting up the enviroment
Hserv expect hugepages (2MiB) to be available.
So ensure you have some with
`sudo bash -c "echo '8192' >> /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"`.
That is an overkill number and only a couple of hugepages are necessary.

Hserv uses pipes for `sendfile` syscall like operation.
These are preallocated and there a quite a few of them 2 fds per pipe * max_connections.
That is 2048 fds just for the pipes. Your open files limit might not be enough in that case use
`ulimit -n 8192` before running hserv.

The executable `tsrv` serves the contents of `./test` on port `3000`.


# Notes

## A bit of wierdness in the architecture
Because I initially wanted to make a more general http server not just a static
file server, I used buf ring. For the use of a static file server a request should realy only take up
a fraction if the single buffer size and any larger request should be responded with `431 Request Header Fields Too Large`.
They are GET requests and should not have content.

So a more efficient buffer scheme is possible.

Currently all the buffers to be used are preallocated before the start of the uring.

## Error Handeling
A lot of errors are not handled gracefully. Mostly because it is not fun to do.
You can kindof see that at the start I did do gracefull error handling but then I didn't.
