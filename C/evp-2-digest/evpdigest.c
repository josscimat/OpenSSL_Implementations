/* gcc evpdigest.c -o evpdigest -pthread -lcrypto -ldl -static-libgcc */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main()
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha1();
    const void *msg = "hola";

    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len = 0;

    // digest
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, strlen(msg));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    printf("Message is: %s\n", (char *) msg);
    printf("Digest is: ");
    for (int i = 0; i < md_len; i++)
    {
        printf("%02x", md_value[i]);
    }
    printf("\n");
    return 0;
}

