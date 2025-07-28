#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include "fae.h"

int configure_ssl_ctx(SSL_CTX *ctx, const char *cipher_list, const char *curves_list, const char *sigalgs, const unsigned char *alpn_protos, size_t alpn_len,uint16_t min_version, uint16_t max_version){

    // Set Cipher list
    if (!SSL_CTX_set_cipher_list(ctx, cipher_list)){
        fprintf(stderr, "Error setting Cipher list %s\n", cipher_list);
        return 0;
    }

    // Set curves
    if (!SSL_CTX_set1_curves_list(ctx, curves_list)){
        fprintf(stderr, "Error setting curves %s\n", curves_list);
        return 0;
    }

    // Set signature algorithms
    if (!SSL_CTX_set1_sigalgs_list(ctx, sigalgs)){
        fprintf(stderr, "Error setting signature algorithms %s\n", sigalgs);
        return 0;
    }

    // Set minimum protocol version
    if (!SSL_CTX_set_min_proto_version(ctx, min_version)){
        fprintf(stderr, "Error setting minimum protocol version\n");
        return 0;
    }

    // // Set maximum protocol version
    if (!SSL_CTX_set_max_proto_version(ctx, max_version)){
        fprintf(stderr, "Error setting maximum protocol version");
        return 0;
    }

    // Set ALPN protos
    if (SSL_CTX_set_alpn_protos(ctx, alpn_protos, alpn_len) != 0){
        fprintf(stderr, "Error setting ALPN protos\n");
        return 0;
    }

    printf("---------------------SSL SET SUCCESSFULLY------------------\n");
    return 1;
}

GetResponse tls_get_request(SSL_CTX *ctx, const char *hostname, int port, const char *request_path) {
    GetResponse result;
    result.error_res = -1;
    result.response = NULL;
    int sockfd;
    struct hostent *server;
    struct sockaddr_in serv_addr;

    // Create TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return result;
    }

    server = gethostbyname(hostname);
    if (!server) {
        fprintf(stderr, "No such host: %s\n", hostname);
        close(sockfd);
        return result;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return result;
    }

    // Create SSL object and bind to socket
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "SSL_new failed\n");
        close(sockfd);
        return result;
    }

    SSL_set_fd(ssl, sockfd);

    if (!SSL_set_tlsext_host_name(ssl, hostname)) {
        fprintf(stderr, "Failed to set SNI\n");
        SSL_free(ssl);
        close(sockfd);
        return result;
    }
    // Perform TLS handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sockfd);
        return result;
    }
    const unsigned char *alpn_proto = NULL;
    unsigned int alpn_len = 0;

    SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);

    if (alpn_len > 0) {
        printf("Negotiated ALPN protocol: %.*s\n", alpn_len, alpn_proto);
    } else {
        printf("No ALPN protocol was negotiated.\n");
    }

    // Prepare and send GET request
    char request[1024];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
             request_path, hostname);

    SSL_write(ssl, request, strlen(request));

    // Read and print the response
    size_t total_size = 0;
    size_t buf_size = 4096;
    char *response = malloc(buf_size);
    if (!response) {
        SSL_free(ssl);
        close(sockfd);
        return result;
    }
    int n;
    while ((n = SSL_read(ssl, response + total_size, buf_size - total_size - 1)) > 0) {
        total_size += n;
        if (total_size > buf_size - 2048) { // expand buffer
            buf_size *= 2;
            response = realloc(response, buf_size);
            if (!response) {
                SSL_free(ssl);
                close(sockfd);
                return result;
            }
        }
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    result.error_res = 0;
    result.response = response;
    return result;
}

void free_get_response(GetResponse resp) {
    if (resp.response) {
        free(resp.response);
    }
}