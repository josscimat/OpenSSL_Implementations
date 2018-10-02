/* gcc testevprsa15.c -o testevprsa15 -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -I/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

EVP_PKEY *key = NULL;
EVP_MD_CTX *mdctx = NULL;
char *md_value = NULL;
size_t md_len = 0;
int statverify = 0;
int statmdvalue = 0;

int generateKeys(const int sizek)
{
    key = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EVP_PKEY_keygen_init(ctx) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_keygen_init()\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, sizek) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_CTX_set_rsa_keygen_bits()\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    
    if (EVP_PKEY_keygen(ctx, &key) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_keygen()\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx); 
    return 0;
}

int sign(const EVP_MD *md, const void *msg)
{
    mdctx = EVP_MD_CTX_create();
    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, key) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignInit()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestSignUpdate(mdctx, msg, strlen(msg)) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignUpdate()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestSignFinal(mdctx, NULL, &md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignFinal()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    md_value = OPENSSL_malloc(sizeof(md_len));
    if (EVP_DigestSignFinal(mdctx, md_value, &md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignFinal()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int verify(const EVP_MD *md, const void *msg)
{
    mdctx = EVP_MD_CTX_create();
    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, key) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyInit()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg)) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyUpdate()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    //statverify = EVP_DigestVerifyFinal(mdctx, md_value, md_len);
    if (EVP_DigestVerifyFinal(mdctx, md_value, md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyFinal()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int signTest(const EVP_MD *md, const void *msg)
{
    mdctx = EVP_MD_CTX_create();
    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, key) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignInit()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestSignUpdate(mdctx, msg, strlen(msg)) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignUpdate()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestSignFinal(mdctx, NULL, &md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignFinal()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (statmdvalue == 0)
    {
        md_value = OPENSSL_malloc(sizeof(md_len));
        statmdvalue = 1;
    }
    if (EVP_DigestSignFinal(mdctx, md_value, &md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignFinal()\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int printResults(const int sizek, const EVP_MD *md, const void *msg)
{
    const char *hash = OBJ_nid2sn(EVP_MD_type(md));
    printf("Key: %i bits\n", sizek);
    printf("Digest: %s\n", hash);
    printf("Message Size: %i bits\n", (int) strlen(msg));
    printf("Signature Size: %i bits\n", (int) md_len); 
    //funciones para determinar los tiempos de ejecucion de la firma y verificacion
    if (statverify == 1)
    {
        printf("verify: OK\n");       
    }
    time_t seconds = time(NULL);
    printf("Seconds: %li\n", (long int) seconds);
    return 0;
}

int main()
{
    const int sizek = 1024;
    const EVP_MD *md = EVP_sha1();
    const void *c32 = "hola";
    const void *c255 = "holaholaholaholaholaholaholaholaholaholaholaholaholaholaholahola";
    
    generateKeys(sizek);

    //sign(md, c255);

    //verify(md, c255);

    //printResults(sizek, md, c255);

    //-----------------------------------------------------------------------------  
    long long countsign = 0;
    time_t sec1sign = time(NULL);
    long int sec2sign = sec1sign + 10;
    printf("Starting Sign Counting...\n");
    while (sec1sign <= sec2sign)
    {
        signTest(md, c32);
        countsign++;
        sec1sign = time(NULL);
    }
    printf("Count Sign: %lli\n", countsign);

    //-----------------------------------------------------------------------------
    long long countverify = 0;
    time_t sec1verify = time(NULL);
    long int sec2verify = sec1verify + 10;
    printf("Starting Verify Counting...\n");
    while (sec1verify <= sec2verify)
    {
        verify(md, c32);
        countverify++;
        sec1verify = time(NULL);
    }
    printf("Count Verify: %lli\n", countverify);
     
    return 0;
}




