/* gcc evprsa15v1.c -o evprsa15v1 -pthread -lcrypto -ldl -static-libgcc */

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
    const EVP_MD *md = EVP_sha1();
    const void *msg = "hola";

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *mdctxs = NULL;
    EVP_MD_CTX *mdctxv = NULL;
    char *md_value = NULL;
    size_t md_len = 0;
    int statverify = 0;

    // generateKeys
    key = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, sizek);
    EVP_PKEY_keygen(ctx, &key);

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

    // sign
    mdctxs = EVP_MD_CTX_create();
    EVP_DigestSignInit(mdctxs, &ctx, md, NULL, key);
    EVP_DigestSignUpdate(mdctxs, &msg, strlen(msg));
    EVP_DigestSignFinal(mdctxs, NULL, &md_len);
    md_value = OPENSSL_malloc(md_len);
    EVP_DigestSignFinal(mdctxs, md_value, &md_len);

    // verify
    mdctxv = EVP_MD_CTX_create();
    EVP_DigestVerifyInit(mdctxv, &ctx, md, NULL, key);
    EVP_DigestVerifyUpdate(mdctxv, &msg, strlen(msg));
    statverify = EVP_DigestVerifyFinal(mdctxv, md_value, md_len);
    
    // printResults
    const char *hash = OBJ_nid2sn(EVP_MD_type(md));
    printf("Key: %i\n", sizek);
    printf("Digest: %s\n", hash);
    printf("Message: %s\n", (char *) msg);
    printf("Message Size: %i bits\n", (int) strlen(msg) * 8);
    printf("Signature Size: %i\n", (int) md_len); 
    if (statverify == 1)
    {
        printf("verify: OK\n");       
    }
    else
    {
        printf("verify: FAIL\n");       
    }

    return 0;
}


