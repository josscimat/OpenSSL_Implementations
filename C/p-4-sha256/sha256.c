/* gcc sha256.c -o sha256 -pthread -lcrypto -ldl -static-libgcc */

#include <stdio.h>
#include <openssl/sha.h>

int main()
{
    char* str = "hola mundo";
    int i = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, sizeof(str));
    SHA256_Final(hash, &sha256);
    printf("String is: %s\n", str);
    printf("SHA256 is: ");
    for (i = 0; i < sizeof(hash); i++)
        printf("%02x", hash[i]);
    printf("\n");
    return 0;
}

