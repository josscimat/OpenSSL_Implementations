/* gcc evpdigest.c -o evpdigest -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -L/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main()
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha1();
    char mess1[] = "Hola Mundo";
    //const void *mess2 = "Adios Mundo";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len, i;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, &mess1, strlen(mess1));
    //EVP_DigestUpdate(mdctx, &mess2, strlen(mess2));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    EVP_cleanup(); 
    printf("Digest is: ");
    for(i = 0; i < md_len; i++)
           printf("%02x", md_value[i]);
    printf("\n");
    return 0;
}

