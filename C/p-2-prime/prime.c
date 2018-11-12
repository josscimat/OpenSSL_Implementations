/* gcc prime.c -o prime -pthread -lcrypto -ldl -static-libgcc */

#include <stdio.h>
#include <openssl/bn.h>

int main()
{
    BIGNUM *ret = BN_new(); 
    int bits = 1024; 
    int safe = 0;
    int stateprime = BN_generate_prime_ex(ret, bits, safe, NULL, NULL, NULL); 
    printf("Estado del BN_generate_prime_ex: %i\n", stateprime);
    BN_free(ret); 
    return 0;
}
