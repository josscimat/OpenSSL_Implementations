/* gcc evpkeygen.c -o evpkeygen -pthread -lcrypto -ldl -static-libgcc */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define PRIFILE "private.pem"
#define PUBFILE "public.pem"

int main()
{
    int sizek = 1024;

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    // generateKeys
    key = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, sizek);
    EVP_PKEY_keygen(ctx, &key);
    
    // Generacion de certificados PEM privado y publico
    FILE *fp;
    BIO *out = NULL;
    fp = fopen(PRIFILE, "w");
    out = BIO_new_fp(fp, BIO_NOCLOSE);
    BIO_set_flags(out, BIO_FLAGS_WRITE);
    int stat4 = EVP_PKEY_print_private(out, key, 0, NULL);
    fclose(fp);
    BIO_free(out);
    fp = fopen(PUBFILE, "w");
    out = BIO_new_fp(fp, BIO_NOCLOSE);
    BIO_set_flags(out, BIO_FLAGS_WRITE);
    int stat5 = EVP_PKEY_print_public(out, key, 0, NULL);
    fclose(fp);
    BIO_free(out);      
    
    return 0;
}

