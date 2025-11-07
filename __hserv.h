#include "_hserv.h"

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <linux/tls.h>
#include <netinet/tcp.h>

#include <theosl/utils/align.h>

static inline struct io_uring_sqe* _hsv_io_uring_get_sqe(struct hsv_engine_t* engine);
static inline struct io_uring_sqe* __hsv_io_uring_get_sqe(struct io_uring* uring); 
static inline int _hsv_send_file_chunk(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx, __off64_t offset); 

static inline void _hsv_free_request_buffers(struct hsv_engine_t* engine, struct hsv_request* request);
static inline void _hsv_ibufring_return(struct hsv_engine_t* engine, char* buffer, uint16_t buf_id);
static inline struct io_uring_sqe* _hsv_enqueue_read(struct hsv_engine_t* engine, struct hsv_request* request, uint64_t req_indx);

static inline int _hsv_request_buffer_add(struct hsv_request *request, const struct _hsv_request_buffer *const buffer);
static inline int _hsv_request_buffer_input_buffer_add(struct hsv_request *request, int indx);
static inline int _hsv_request_buffer_iov_add(struct hsv_request *request, void* iov_base, size_t iov_len);

void _hsv_handle_sec_accept(struct hsv_engine_t* engine, struct io_uring_cqe *cqe);
void _hsv_handle_ssl_read(struct hsv_engine_t* engine, struct io_uring_cqe *cqe);
void _hsv_handle_ssl_write(struct hsv_engine_t* engine, struct io_uring_cqe *cqe);
void _hsv_handle_accept(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_read(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_socket_close_cqe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_close_request(struct hsv_engine_t* engine, uint64_t request_index);
void _hsv_handle_send_file_out_pipe(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_initial_send(struct hsv_engine_t* engine, struct io_uring_cqe* cqe);
void _hsv_handle_ssl_setsockopt(struct hsv_engine_t *engine, struct io_uring_cqe *cqe); 

#define __HSV_REQUEST_BUFFER_WRITE_BUFFER_INDEX 0
#define __HSV_REQUEST_BUFFER_READ_BUFFER_INDEX 1
