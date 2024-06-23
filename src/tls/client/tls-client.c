#include "tls-client.h"

#include <asm-generic/errno.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Create socket and connect to destination server.
 *
 * @param const char *hostname -> Domain of the website.
 * @param const char *port -> Port of the connection (normally specifies the
 * protocol).
 * @return int -> socket;
 */
static int create_client_socket(const char *hostname, const char *port) {
    // Instantiate socket.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        fprintf(stderr, "(error) Error creating socket.\n");
        return -1;
    }

    // Configure socket to be reusable.
    int option = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // Set socket to non-blocking mode.
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        fprintf(stderr, "(error) Error setting socket to non-blocking mode.\n");
        close(sock);
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *server = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Get IP of the server.
    int status;
    if ((status = getaddrinfo(hostname, port, &hints, &server)) != 0) {
        fprintf(stderr, "(error) Could not resolve hostname: %s\n",
               gai_strerror(status));
        return -1;
    }

    if (connect(sock, server->ai_addr, server->ai_addrlen) == -1 &&
        errno != EINPROGRESS) {
        fprintf(stderr, "(error) Error connecting to server.\n");
        close(sock);
        freeaddrinfo(server);
        return -1;
    }

    freeaddrinfo(server);

    return sock;
}

/**
 * Compare domain with domain specified in configuration file. If they match,
 * the SNI will be changed, according to the configuration. To verify the match,
 * regex is used.
 *
 * @param sni_change -> List of domains for which the SNI should be changed.
 * @param domain -> Domain of the current website.
 * @return -> SNI.
 */
char *get_sni_from_domain(struct sni_change *sni_changes, char *domain) {
    if (sni_changes == NULL)
        return domain;

    for (int i = 0; strlen(sni_changes[i].domain) != 0; ++i) {
        regex_t regex;
        int invalid_regex = regcomp(&regex, sni_changes[i].domain, 0);
        if (invalid_regex)
            return false;

        // Compare domain with regex to search a match.
        // Ex: example is a match of www.example.com
        if (regexec(&regex, domain, 0, NULL, 0) == 0)
            return sni_changes[i].sni;
    }

    return domain;
}

/**
 * Create a TLS connection with the destination host.
 *
 * In the handshake, change the server_name extension to the value available in
 * the struct ssl_connection.
 *
 * @param ctx -> Context to create SSL connections.
 * @param sni_change -> List of domains for which the SNI should be changed.
 * @param ssl_connection -> Information of the connection, where the connection
 * will be saved.
 * @return int -> 0 if success, -1 otherwise.
 */
int create_TLS_connection_with_host_with_changed_SNI(
    SSL_CTX *ctx, struct sni_change *sni_changes,
    struct ssl_connection *ssl_connection, bool no_verify) {

    fprintf(stdout, "(info) Creating TLS connection:\n");
    fprintf(stdout, "(info) Hostname: %s\n", ssl_connection->hostname);
    fprintf(stdout, "(info) SNI: %s\n", ssl_connection->sni);
    fprintf(stdout, "(info) Port: %s\n", ssl_connection->port);

    // Create a factory of SSL objects. TLS_client_method() specifies that we
    // want the context for creating clients.
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "(error) Failed to create the SSL_CTX.\n");
        return -1;
    }

    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);

    // Configure the client to abort the handshake if certificate
    // verification fails.
    if (!no_verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    // Use the default trusted certificate store
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "(error) Failed to set the default trusted certificate store.\n");
        return -1;
    }

    // Require a minimum TLS version of TLSv1.2.
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "(error) Failed to set the minimum TLS protocol version.\n");
        return -1;
    }

    // Create an SSL object to represent the TLS connection
    ssl_connection->host.connection = SSL_new(ctx);
    if (ssl_connection->host.connection == NULL) {
        fprintf(stderr, "(error) Failed to create the SSL object.\n");
        return -1;
    }

    // Create the underlying transport socket and associate it with the
    // connection.
    int client_fd =
        create_client_socket(ssl_connection->hostname, ssl_connection->port);
    if (client_fd <= 0) {
        fprintf(stderr, "(error) Failed to create the socket.\n");
        return -1;
    }
    SSL_set_fd(ssl_connection->host.connection, client_fd);

    ssl_connection->host.fd = client_fd;

    // Update SNI if needed.
    strcpy(ssl_connection->sni,
           get_sni_from_domain(sni_changes, ssl_connection->hostname));

    // Tell the server during the handshake which hostname we are attempting
    // to connect to in case the server supports multiple hosts. The hostname
    // used is also called SNI. This is the part that we want to change.
    if (!SSL_set_tlsext_host_name(ssl_connection->host.connection,
                                  ssl_connection->sni)) {
        fprintf(stderr, "(error) Failed to set the SNI hostname.\n");
        return -1;
    }

    fprintf(stdout, "(debug) SNI changed to: %s\n", ssl_connection->sni);

    // Ensure we check during certificate verification that the server has
    // supplied a certificate for the hostname that we were expecting. This is
    // optional in our process, for the moment.
    if (!SSL_set1_host(ssl_connection->host.connection,
                       ssl_connection->hostname)) {
        fprintf(stderr, "(error) Failed to set the certificate verification hostname.");
        return -1;
    }

    fprintf(stdout, "(debug) Attempt to handshake with %s...\n",
           ssl_connection->hostname);

    // Do the handshake with the server
    if (do_tls_handshake(ssl_connection->host.connection, client_fd, false) ==
        -1) {
        fprintf(stderr, "(error) Handshake error with the user.");
        return -1;
    }

    fprintf(stdout, "(debug) Successful handshake!\n");

    return 0;
}
