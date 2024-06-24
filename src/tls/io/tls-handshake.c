#include "tls-handshake.h"
#include <openssl/err.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * Do SSL handshake with data received in the socket.
 *
 * Assumes that non-blocking sockets are being used.
 *
 * @param ssl -> SSL connection.
 * @param fd -> FD of the socket.
 * @param is_server -> 1 if it is a server, 0 if client.
 * @return -> 1 if success, 0 otherwise.
 */
int do_tls_handshake(SSL *ssl, int fd, bool is_server) {

    fd_set read_fds;
    int max_fd = fd + 1;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    // As non-blocking sockets are being used, a while loop is mandatory to call
    // the function until a success/error is returned.
    while (1) {
        int status = is_server ? SSL_accept(ssl) : SSL_connect(ssl);

        // Connection made successfully
        if (status == 1)
            break;

        int decodedError = SSL_get_error(ssl, status);

        // Error while creating the connection.
        if (decodedError == SSL_ERROR_WANT_READ) {
            int result = select(max_fd, &read_fds, NULL, NULL, NULL);

            if (result == -1) {
                fprintf(stderr,
                        "(error) Read-select error in handshake TLS.\n");
                return -1;
            }
        } else if (decodedError == SSL_ERROR_WANT_WRITE) {
            int result = select(max_fd, NULL, &read_fds, NULL, NULL);

            if (result == -1) {
                fprintf(stderr,
                        "(error) Write-select error in handshake TLS.\n");
                return -1;
            }
        } else if (decodedError == SSL_ERROR_SSL) {
            char msg[4096];
            ERR_error_string_n(ERR_get_error(), msg, sizeof(msg));
            fprintf(stderr, "(error) TLS %s error: %s\n", is_server ? "server" : "client", msg);
            return -1;
        } else {
            fprintf(stderr, "(error) Error creating SSL connection.  err=%x\n",
                    decodedError);
            return -1;
        }
    }

    return 0;
}

/**
 * Clean and free a struct ssl_connection.
 *
 * @param ssl_connection -> struct ssl_connection to be cleaned.
 * @param should_free -> should free and close sockets or not.
 */
void clean_SSL_connection(struct ssl_connection *ssl_connection,
                          bool should_free) {
    if (should_free) {
        fprintf(stdout,
                "(info) Connection closed (user-fd/host-fd[hostname]: "
                "%d/%d[%s]).\n",
                ssl_connection->user.fd, ssl_connection->host.fd,
                ssl_connection->hostname);

        if (ssl_connection->user.connection != NULL)
            SSL_free(ssl_connection->user.connection);

        if (ssl_connection->host.connection != NULL)
            SSL_free(ssl_connection->host.connection);

        if (ssl_connection->user.fd != 0)
            close(ssl_connection->user.fd);

        if (ssl_connection->host.fd != 0)
            close(ssl_connection->host.fd);
    }

    ssl_connection->user.fd = 0;
    ssl_connection->user.connection = NULL;

    ssl_connection->host.fd = 0;
    ssl_connection->host.connection = NULL;

    memset(ssl_connection->hostname, 0, DOMAIN_MAX_SIZE);
    memset(ssl_connection->sni, 0, DOMAIN_MAX_SIZE);
    memset(ssl_connection->port, 0, PORT_MAX_SIZE);
}
