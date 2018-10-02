/* gcc evprsa15.c -o evprsa15 -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -I/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/*// Includes y Defines generacion de certificados
#include <openssl/bio.h>
#include <openssl/pem.h>

#define PRIFILE "private.pem"
#define PUBFILE "public.pem"*/

int main()
{
    int sizek = 1024;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, sizek);
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx); 

    /*// Generacion de certificados PEM privado y publico
    FILE *fp;
    BIO *out = NULL;
    fp = fopen(PRIFILE, "w");
    out = BIO_new_fp(fp, BIO_NOCLOSE);
    BIO_set_flags(out, BIO_FLAGS_WRITE);
    EVP_PKEY_print_private(out, key, 0, NULL);
    fclose(fp);
    BIO_free(out);
    fp = fopen(PUBFILE, "w");
    out = BIO_new_fp(fp, BIO_NOCLOSE);
    BIO_set_flags(out, BIO_FLAGS_WRITE);
    EVP_PKEY_print_public(out, key, 0, NULL);
    fclose(fp);
    BIO_free(out);*/

    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = EVP_sha1();
    const void *mess1 = "hola mundo";
    char *md_value = NULL;
    size_t md_len = 0;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestSignInit(mdctx, NULL, md, NULL, key);
    EVP_DigestSignUpdate(mdctx, mess1, strlen(mess1));
    EVP_DigestSignFinal(mdctx, NULL, &md_len);
    md_value = OPENSSL_malloc(sizeof((unsigned char *) md_len));
    EVP_DigestSignFinal(mdctx, md_value, &md_len);
    EVP_DigestVerifyInit(mdctx, NULL, md, NULL, key);
    EVP_DigestVerifyUpdate(mdctx, mess1, strlen(mess1));
    int verify = EVP_DigestVerifyFinal(mdctx, md_value, md_len);
    EVP_MD_CTX_free(mdctx);
    
    printf("Key: %i\n", sizek);
    printf("Digest: SHA1\n");
    printf("Message: %s\n", (char *) mess1);
    printf("Signature Size: %i\n", (int) md_len); 
    if (verify == 1)
    {
        printf("verify: OK\n");       
    }

    return 0;
}


