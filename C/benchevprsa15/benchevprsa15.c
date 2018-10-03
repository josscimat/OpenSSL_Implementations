/* gcc benchevprsa15.c -o benchevprsa15 -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -I/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

#include <time.h>
#include <stdio.h>
#include <stdint.h>
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

static inline uint64_t rdtsc(void)
{
    unsigned int eax, edx;
    asm volatile
    (
        "rdtsc" : "=a" (eax), "=d" (edx)
    );
    return ((uint64_t) edx << 32) | eax;
}

int main()
{
    const int sizek = 1024;
    const EVP_MD *md = EVP_sha1();
    const void *c32 = "hola";
    const void *c255 = "holaholaholaholaholaholaholaholaholaholaholaholaholaholaholahola";
    
    generateKeys(sizek);

    uint64_t tmp1 = 0, tmp2 = 0, tiempo1 = 0, tiempo2 = 0, tiempo3 = 0, tiempo4 = 0;
    double tiempos = 0, tiempov;
    tiempo1 = rdtsc();
    //INICIO DEL ALGORIMO A MEDIR
    sign(md, c32);
    //FIN DEL ALGORITMO A MEDIR
    tiempo2 = rdtsc();
    tiempo3 = rdtsc();
    //INICIO DEL ALGORIMO A MEDIR
    verify(md, c32);
    //FIN DEL ALGORITMO A MEDIR
    tiempo4 = rdtsc();
    tmp1 = tiempo2 - tiempo1;
    tmp2 = tiempo4 - tiempo3;
    tiempos = (double) tmp1 / 1900000000; //ciclos de reloj por segundo de la maquina que lo corre
    tiempov = (double) tmp2 / 1900000000; //ciclos de reloj por segundo de la maquina que lo corre 
    printf("\nCiclos de Reloj de la Firma: %lu\n", tmp1);
    printf("\nTiempo en Segundos de la Firma: %f\n", tiempos);
    printf("\nCiclos de Reloj de la Verificacion: %lu\n", tmp2);
    printf("\nTiempo en Segundos de la verificacion: %f\n", tiempov);     
    return 0;
}




