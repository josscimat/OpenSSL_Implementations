/* gcc evpkeygen.c -o evpkeygen -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -I/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

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
    
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    int stat1 = EVP_PKEY_keygen_init(ctx);
    int stat2 = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024);
    int stat3 = EVP_PKEY_keygen(ctx, &key);
    
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
    
    EVP_PKEY_CTX_free(ctx);
    EVP_cleanup();
    
    printf("stat1: %i\n", stat1);
    printf("stat2: %i\n", stat2);
    printf("stat3: %i\n", stat3);
    printf("stat4: %i\n", stat4);    
    printf("stat5: %i\n", stat5);        
    
    return 0;
}

