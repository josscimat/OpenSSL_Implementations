/* gcc evprsa22v2.c -o evprsa22v2 -pthread -lcrypto -ldl -static-libgcc */

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
int statverify = 0;

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
    if ((statverify = EVP_DigestVerifyFinal(mdctxv, md_value, md_len)) != 1)
    {
        printf("Error en la funcion: EVP_DigestVerifyFinal()\n");
        return 1;
    }
    return 0;
}

int printResults(const int sizek, const EVP_MD *md, const void *msg)
{
    const char *hash = OBJ_nid2sn(EVP_MD_type(md));
    printf("Key: %i bits\n", sizek);
    printf("Digest: %s\n", hash);
    printf("Message: %s\n", (char *) msg);
    printf("Message Size: %i bits\n", (int) strlen(msg) * 8);
    printf("Signature Size: %i bits\n", (int) md_len); 
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

int main()
{
    const int sizek = 1024;
    const EVP_MD *md = EVP_sha256();
    const void *msg = "hola";
    
    generateKeys(sizek);
    
    sign(md, msg);

    verify(md, msg);

    printResults(sizek, md, msg);
   
    return 0;
}




