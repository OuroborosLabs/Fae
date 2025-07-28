#ifndef FAE_H
#define FAE_H

#include <openssl/ssl.h>
#include <openssl/tls1.h>

int configure_ssl_ctx(SSL_CTX *ctx,
                        const char *cipher_list,
                        const char *curves_list,
                        const char *sigalgs_list,
                        const unsigned char *alpn_protos,
                        size_t alpn_len,
                        uint16_t min_version,
                        uint16_t max_version);

typedef struct {
    int error_res;
    char *response;
} GetResponse;

GetResponse tls_get_request(SSL_CTX *ctx, const char *hostname, int port, const char *request_path);

void free_get_response(GetResponse resp);

#endif // FAE_H
