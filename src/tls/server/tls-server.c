#include "tls-server.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * Configures the address of the socket.
 *
 * @param address -> Configured address of the socket.
 * @param ip -> IP of the socket.
 * @param port -> Port the socket will listen on.
 */
void set_address(struct sockaddr_in *address, uint32_t ip, uint16_t port) {
    memset(address, 0, sizeof(struct sockaddr_in));
    (*address).sin_family = AF_INET;
    (*address).sin_port = htons(port);
    (*address).sin_addr.s_addr = ip;
}

/**
 * Create a new server socket and return his FD.
 *
 * @param address -> Address of the server.
 * @param port -> Port to access the server.
 * @return -> FD value of the socket.
 */
int create_server_socket(struct sockaddr_in address, int port) {
    int server_fd;

    // Creates a new socket.
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "(error) Failed to create socket.\n");
        exit(EXIT_FAILURE);
    }

    // Configures the socket to reuse address, for debbuging purporses.
    int option = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option,
                   sizeof(option))) {
        fprintf(stderr, "(error) Failed to set reusable configuration.\n");
        exit(EXIT_FAILURE);
    }

    if (fcntl(server_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("(error) Error setting socket to non-blocking mode.\n");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Bind the proxy socket to the proxy address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "(error) Failed to bind proxy socket\n");
        exit(EXIT_FAILURE);
    }

    // Listen for client connections
    if (listen(server_fd, SOMAXCONN) < 0) {
        fprintf(stderr, "(error) Failed to listen for client connections\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "(info) Proxy server listening on port %d\n", port);

    // Returns the FD of the socket.
    return server_fd;
}

/**
 * Configures the certificate used by the server when any connection asks for a
 * certificate. The certificate will contain the hostname as DNS and Common
 * Name.
 *
 * @param ctx -> Context where the certificate will be saved.
 * @param hostname -> Hostname of the destination website. Ex: www.example.com
 */
int create_certificate_for_host(SSL_CTX *ctx, struct root_ca root_ca,
                                const char *hostname) {

    EVP_PKEY *key = NULL;
    X509 *crt = NULL;

    if (generate_certificate(root_ca, &key, &crt, hostname) == -1)
        return -1;

    // Set certificate into the context.
    if (SSL_CTX_use_certificate(ctx, crt) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set key into the context.
    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

/**
 * Extract the hostname and port from the first message sent by the user. When
 * using Firefox to connect to https://www.example.com, the following message is
 * sent:
 *
 * CONNECT www.example.com:443 HTTP/1.1
 * User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101
 * Firefox/115.0 Proxy-Connection: keep-alive Connection: keep-alive Host:
 * www.example.com:443
 *
 * The first line is read, obtaining the hostname and the port from the request.
 *
 * @param message -> Given message.
 * @param hostname -> Return the extracted hostname.
 * @param port -> Return the extracted port.
 * @return -> 0 if success, -1 otherwise.
 */
int extract_hostname(const char *message, char *hostname, char *port) {
    if (sscanf(message, "CONNECT %99[^:]:%s", hostname, port) != 2) {
        fprintf(stderr, "(error) Failed to extract domain.\n");
        return -1;
    }

    return 0;
}

/**
 *
 * @param ctx
 * @param ssl_connection
 * @param server_fd
 * @return
 */
int create_TLS_connection_with_user(SSL_CTX *ctx, struct root_ca root_ca,
                                    struct ssl_connection *ssl_connection,
                                    int server_fd) {
    SSL *ssl;
    struct sockaddr_in client_address;
    unsigned int address_length = sizeof(client_address);

    // Accept incoming connection and assign to a new FD.
    int connection_fd =
        accept(server_fd, (struct sockaddr *)&client_address, &address_length);
    if (connection_fd < 0 && errno != EWOULDBLOCK) {
        fprintf(stderr, "(error) Error in accept.\n");
        exit(0);
    }

    // Set fd of the connection.
    ssl_connection->user.fd = connection_fd;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(connection_fd, &read_fds);
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = RESPONSE_TIMEOUT_MS;

    // If the incoming connection does not send data in the RESPONSE_TIMEOUT_MS,
    // the socket will be closed.
    int status = select(connection_fd + 1, &read_fds, NULL, NULL, &timeout);
    if (status == 0) {
        fprintf(stderr, "(error) Read timed out.\n");
        return -1;
    }

    fprintf(stdout, "(info) Connection fd: %d\n", connection_fd);

    char connect_message[BUFFER_SIZE];

    // Read the CONNECT from the client.
    ssize_t size = read(connection_fd, connect_message, BUFFER_SIZE);
    if (size <= 0) {
        fprintf(stderr, "(error) Error reading user socket.\n");
        return -1;
    }
    connect_message[size] = '\0';

    while (!strstr(connect_message, "\r\n\r\n")) {
        ssize_t read_result = read(connection_fd, connect_message + size, BUFFER_SIZE - size);
        if (read_result <= 0) {
            fprintf(stderr, "(error) Error reading user socket, %zd bytes have been read.\n", size);
            return -1;
        }
        size += read_result;
        connect_message[size] = '\0';
    }

    // Set new connection socket to non-blocking mode.
    if (fcntl(connection_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Error setting socket to non-blocking mode");
        close(connection_fd);
        exit(EXIT_FAILURE);
    }

    // Get the hostname and the port.
    extract_hostname(connect_message, ssl_connection->hostname,
                     ssl_connection->port);
    strcpy(ssl_connection->sni, ssl_connection->hostname);

    // Send a message to the client informing that the connection was made, to
    // create a direct TLS connection with it.
    const char *proxy_response = DEFAULT_RESPONSE_TO_CLIENT;
    ssize_t bytes_sent =
        write(connection_fd, proxy_response, strlen(proxy_response));
    if (bytes_sent < 0) {
        perror("(error) Failed to send response to the client.\n");
        return -1;
    }

    fprintf(stdout, "(debug) Message sent!\n");

    // Create a new certificate with the hostname.
    if (create_certificate_for_host(ctx, root_ca, ssl_connection->hostname) ==
        -1)
        return -1;

    // Create SSL connection with changed certificate.
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connection_fd);

    if (do_tls_handshake(ssl, connection_fd, true) == -1)
        return -1;

    // Assign new TLS connection to user.
    ssl_connection->user.connection = ssl;

    return EXIT_SUCCESS;
}
