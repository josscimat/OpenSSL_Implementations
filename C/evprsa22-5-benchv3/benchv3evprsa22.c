/* gcc benchv3evprsa22.c -o benchv3evprsa22 -pthread -lcrypto -ldl -static-libgcc */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
    
static inline uint64_t rdtsc(void)
{
    unsigned int eax, edx;
    asm volatile("rdtsc" : "=a" (eax), "=d" (edx));
    return ((uint64_t) edx << 32) | eax;
}

int main()
{
    const int sizek = 1024;
    const EVP_MD *md = EVP_sha256();
    const void *msg = "hola";

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *mdctxs = NULL;
    EVP_MD_CTX *mdctxv = NULL;
    char *md_value = NULL;
    size_t md_len = 0;
    uint64_t tmp1 = 0, tmp2 = 0, tiempo1 = 0, tiempo2 = 0, tiempo3 = 0, tiempo4 = 0;
    double tiempos = 0, tiempov = 0;
    long long int ciclosign = 0, cicloverify = 0;
    int totalsign = 0, totalverify = 0;
    
    // generateKeys
    key = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, sizek);
    EVP_PKEY_keygen(ctx, &key);

    for (int i = 0; i < 10000; i++)
    {
        // sign
        mdctxs = EVP_MD_CTX_create();
        EVP_DigestSignInit(mdctxs, &ctx, md, NULL, key);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -2);
        EVP_DigestSignUpdate(mdctxs, &msg, strlen(msg));
        EVP_DigestSignFinal(mdctxs, NULL, &md_len);
        md_value = OPENSSL_malloc(md_len);
        tiempo1 = rdtsc();
        //INICIO DEL ALGORIMO A MEDIR
        EVP_DigestSignFinal(mdctxs, md_value, &md_len);
        //FIN DEL ALGORITMO A MEDIR
        tiempo2 = rdtsc();

        // verify
        mdctxv = EVP_MD_CTX_create();
        EVP_DigestVerifyInit(mdctxv, &ctx, md, NULL, key);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -2);
        EVP_DigestVerifyUpdate(mdctxv, &msg, strlen(msg));
        tiempo3 = rdtsc();
        //INICIO DEL ALGORIMO A MEDIR
        EVP_DigestVerifyFinal(mdctxv, md_value, md_len);
        //FIN DEL ALGORITMO A MEDIR
        tiempo4 = rdtsc();

        tmp1 = tiempo2 - tiempo1;
        tmp2 = tiempo4 - tiempo3;
        ciclosign = ciclosign + tmp1;
        cicloverify = cicloverify + tmp2;
    }

    totalsign = ciclosign / 10000;
    totalverify = cicloverify / 10000;

    /*tiempos = (double) totalsign / 2530000000; //ciclos de reloj por segundo de la maquina que lo corre
    tiempov = (double) totalverify / 2530000000; //ciclos de reloj por segundo de la maquina que lo corre*/
    tiempos = (double) totalsign / 2800000000; //ciclos de reloj por segundo de la maquina que lo corre
    tiempov = (double) totalverify / 2800000000; //ciclos de reloj por segundo de la maquina que lo corre 
    printf("\nCiclos de Reloj de la Firma: %lu\n", tmp1);
    printf("\nTiempo en Segundos de la Firma: %f\n", tiempos);
    printf("\nCiclos de Reloj de la Verificacion: %lu\n", tmp2);
    printf("\nTiempo en Segundos de la verificacion: %f\n", tiempov);     
    return 0;
}




