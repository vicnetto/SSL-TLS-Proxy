#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#ifndef INCLUDE_TLS_HANDSHAKE_H
#define INCLUDE_TLS_HANDSHAKE_H
#include "../io/tls-handshake.h"
#endif

#include <openssl/ssl.h>

int create_TLS_connection_with_host_with_changed_SNI(
    SSL_CTX *ctx, struct sni_change *sni_changes,
    struct ssl_connection *ssl_connection, bool no_verify);

#endif // !TLS_CLIENT_H
