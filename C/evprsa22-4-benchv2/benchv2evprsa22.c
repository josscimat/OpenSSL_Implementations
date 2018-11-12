/* gcc benchv2evprsa22.c -o benchv2evprsa22 -pthread -lcrypto -ldl -static-libgcc */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

EVP_PKEY *key = NULL;
EVP_PKEY_CTX *ctx = NULL;
EVP_MD_CTX *mdctxs = NULL;
EVP_MD_CTX *mdctxv = NULL;
char *md_value = NULL;
size_t md_len = 0;

int generateKeys(const int sizek)
{
    key = EVP_PKEY_new();
    ctx = EVP_PKEY_CTX_new(key, NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
    if (EVP_PKEY_keygen_init(ctx) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_keygen_init()\n");
        return 1;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, sizek) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_CTX_set_rsa_keygen_bits()\n");
        return 1;
    }
    
    if (EVP_PKEY_keygen(ctx, &key) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_keygen()\n");
        return 1;
    }
    return 0;
}

int sign(const EVP_MD *md, const void *msg)
{
    mdctxs = EVP_MD_CTX_create();
    if (EVP_DigestSignInit(mdctxs, &ctx, md, NULL, key) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignInit()\n");
        return 1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_CTX_set_rsa_padding()\n");
        return 1;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -2) != 1) 
    {
        printf("Error en la funcion: EVP_PKEY_CTX_set_rsa_pss_saltlen()\n");
        return 1;
    }
    if (EVP_DigestSignUpdate(mdctxs, &msg, strlen(msg)) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignUpdate()\n");
        return 1;
    }
    if (EVP_DigestSignFinal(mdctxs, NULL, &md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignFinal()\n");
        return 1;
    }
    md_value = OPENSSL_malloc(md_len);
    if (EVP_DigestSignFinal(mdctxs, md_value, &md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestSignFinal()\n");
        return 1;
    }
    return 0;
}

int verify(const EVP_MD *md, const void *msg)
{
    mdctxv = EVP_MD_CTX_create();
    if (EVP_DigestVerifyInit(mdctxv, &ctx, md, NULL, key) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyInit()\n");
        return 1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1)
    {
        printf("Error en la funcion: EVP_PKEY_CTX_set_rsa_padding()\n");
        return 1;
    }
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -2) != 1) 
    {
        printf("Error en la funcion: EVP_PKEY_CTX_set_rsa_pss_saltlen()\n");
        return 1;
    }
    if (EVP_DigestVerifyUpdate(mdctxv, &msg, strlen(msg)) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyUpdate()\n");
        return 1;
    }
    if (EVP_DigestVerifyFinal(mdctxv, md_value, md_len) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyFinal()\n");
        return 1;
    }
    return 0;
}

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
    uint64_t tmp1 = 0, tmp2 = 0, tiempo1 = 0, tiempo2 = 0, tiempo3 = 0, tiempo4 = 0;
    double tiempos = 0, tiempov = 0;
    
    generateKeys(sizek);
    
    tiempo1 = rdtsc();
    //INICIO DEL ALGORIMO A MEDIR
    sign(md, &msg);
    //FIN DEL ALGORITMO A MEDIR
    tiempo2 = rdtsc();
    tiempo3 = rdtsc();
    //INICIO DEL ALGORIMO A MEDIR
    verify(md, &msg);
    //FIN DEL ALGORITMO A MEDIR
    tiempo4 = rdtsc();

    /*EVP_PKEY_CTX_free(ctx);
    EVP_MD_CTX_free(mdctxs); 
    EVP_MD_CTX_free(mdctxv);*/

    tmp1 = tiempo2 - tiempo1;
    tmp2 = tiempo4 - tiempo3;
    /*tiempos = (double) tmp1 / 2530000000; //ciclos de reloj por segundo de la maquina que lo corre
    tiempov = (double) tmp2 / 2530000000; //ciclos de reloj por segundo de la maquina que lo corre*/
    tiempos = (double) tmp1 / 2800000000; //ciclos de reloj por segundo de la maquina que lo corre
    tiempov = (double) tmp2 / 2800000000; //ciclos de reloj por segundo de la maquina que lo corre 
    printf("\nCiclos de Reloj de la Firma: %lu\n", tmp1);
    printf("\nTiempo en Segundos de la Firma: %f\n", tiempos);
    printf("\nCiclos de Reloj de la Verificacion: %lu\n", tmp2);
    printf("\nTiempo en Segundos de la verificacion: %f\n", tiempov);     
    return 0;
}




