#include "cert.h"

#include <openssl/conf.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>

/**
 * Load root cert and root key to sign the generated certificates.
 *
 * @param root_ca -> Struct containing the location of the cert/key.
 * @param key_location -> Location of the key.
 * @param cert_location -> Location of the certificate.
 * @param key_password -> Key password.
 * @return -> 0 if success, -1 otherwise.
 */
int load_root_ca_key_and_crt(struct root_ca *root_ca, char *key_location,
                             char *cert_location, char *key_password) {
    root_ca->root_ca_key = NULL;
    root_ca->root_ca_crt = NULL;
    BIO *bio = NULL;

    // Load certificate.
    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, cert_location))
        goto error;

    root_ca->root_ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!root_ca->root_ca_crt)
        goto error;

    BIO_free_all(bio);

    // Load private key.
    bio = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bio, key_location))
        goto error;

    root_ca->root_ca_key =
        PEM_read_bio_PrivateKey(bio, NULL, NULL, key_password);

    BIO_free_all(bio);

    return 0;
error:
    // Free everything in case of error.
    BIO_free_all(bio);
    X509_free(root_ca->root_ca_crt);
    EVP_PKEY_free(root_ca->root_ca_key);
    return -1;
}

/**
 * Generate the key intended for use with the destination website. Once the key
 * is created, it sign itself to demonstrate possession of the private key.
 *
 * @param key -> Created key.
 * @param req -> Created signature request.
 * @param hostname -> Hostname (ex: www.example.com) to be used as Common Name.
 * @return -> 0 if success, -1 otherwise.
 */
int generate_certificate_key(EVP_PKEY **key, X509_REQ **req,
                             const char *hostname) {
    // Create key
    *key = EVP_PKEY_new();
    if (!*key)
        goto error;

    // Create certificate request
    *req = X509_REQ_new();
    if (!*req)
        goto error;

    // After the creation of the key, now it gives a random RSA value to it.
    if ((*key = EVP_RSA_gen(RSA_KEY_BITS)) == NULL) {
        goto error;
    }

    // Associate the key with the certificate.
    X509_REQ_set_pubkey(*req, *key);

    // Set information about the certificate (distinguished name).
    X509_NAME *name = X509_REQ_get_subject_name(*req);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (const unsigned char *)DN_COUNTRY, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
                               (const unsigned char *)DN_STATE, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                               (const unsigned char *)DN_LOCALITY, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (const unsigned char *)DN_ORGANIZATION, -1, -1,
                               0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                               (const unsigned char *)DN_ORGANIZATION_UNIT, -1,
                               -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)hostname, -1, -1, 0);

    // Self-sign the certificate to show that we possess the private key
    // associated with the certificate.
    if (!X509_REQ_sign(*req, *key, EVP_sha256()))
        goto error;

    return 0;
error:
    // Free everything if it is not needed.
    EVP_PKEY_free(*key);
    X509_REQ_free(*req);
    return -1;
}

/**
 * Create random serial to be used by the recently created certificate.
 *
 * @param crt -> New certificate.
 * @return -> 0 if success, -1 otherwise.
 */
int generate_random_serial(X509 *crt) {
    unsigned char serial_bytes[20];

    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        fprintf(stderr, "(error) Failed to create random sequence os bytes!\n");

        return -1;
    }

    // Transform into number and then to ASN1, to be used as a serial number.
    BIGNUM *bn_serial = BN_new();
    BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn_serial);
    ASN1_INTEGER *asn_serial = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(bn_serial, asn_serial);

    // Ensure the serial number is positive (make it non-negative)
    if (BN_is_negative(bn_serial)) {
        BN_set_negative(bn_serial, 0);
    }

    X509_set_serialNumber(crt, asn_serial);

    ASN1_INTEGER_free(asn_serial);
    BN_free(bn_serial);

    return 0;
}

/**
 * Sign the certificate generated for the specific website. A hostname is passed
 * as parameter to assign the subject_alt_name, which must contain the website
 * for browsers to recognize the authenticity of the certificate.
 *
 * @param ca_key -> Root key.
 * @param ca_crt -> Root certificate.
 * @param key -> New key.
 * @param crt -> New certificate.
 * @param hostname -> Domain (ex: www.example.com).
 * @return -> 0 if success, -1 otherwise.
 */
int sign_certificate(EVP_PKEY *ca_key, const X509 *ca_crt, EVP_PKEY **key,
                     X509 **crt, const char *hostname) {

    // Create private key and request CSR.
    X509_REQ *req = NULL;
    if (generate_certificate_key(key, &req, hostname) == -1)
        return -1;

    *crt = X509_new();
    if (!*crt)
        goto error;

    // Set metadata of the certificate.
    X509_set_version(*crt, 2);
    X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));
    X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
    X509_gmtime_adj(X509_get_notBefore(*crt), 0);
    X509_gmtime_adj(X509_get_notAfter(*crt), 60 * 60 * 24 * 365 * 5); // 5 years

    // Get public key and set to the certificate.
    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(*crt, req_pubkey);

    if (generate_random_serial(*crt) == -1)
        goto error;

    // Set the SAN (subjectNameAlt) to the domain.
    GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
    GENERAL_NAME *gen = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();
    ASN1_STRING_set(ia5, hostname, (int)strlen(hostname));
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    sk_GENERAL_NAME_push(gens, gen);
    X509_add1_ext_i2d(*crt, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);

    // Sign the certificate.
    if (X509_sign(*crt, ca_key, EVP_sha256()) == 0)
        goto error;

    // Free everything.
    X509_REQ_free(req);
    GENERAL_NAMES_free(gens);

    return 0;
error:
    X509_REQ_free(req);
    EVP_PKEY_free(*key);
    X509_free(*crt);

    return -1;
}

/**
 * Load the root certificate, create a new certificate for the website and signs
 * it to be used in a SSL connection.
 *
 * @param root_ca -> Information about the root ca.
 * @param key -> Created key.
 * @param crt -> Created certificate.
 * @param hostname -> Domain (ex: www.example.com).
 * @return -> 0 if success, -1 otherwise.
 */
int generate_certificate(struct root_ca root_ca, EVP_PKEY **key, X509 **crt,
                         const char *hostname) {

    // Generate signed key and certificate by the CA.
    int ret = sign_certificate(root_ca.root_ca_key, root_ca.root_ca_crt, key,
                               crt, hostname);
    if (ret == -1) {
        fprintf(stderr, "(error) Failed to sign certificate!\n");
        return -1;
    }

    return 0;
}
