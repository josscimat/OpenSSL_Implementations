/* gcc rsakeys.c -o rsakeys -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -L/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

int main()
{
    BIGNUM *ret = BN_new(); 
    int bits = 1024; 
    int safe = 0;
    int stateprime = BN_generate_prime_ex(ret, bits, safe, NULL, NULL, NULL); 
    
    RSA *rsa = RSA_new(); 
    int statekey = RSA_generate_key_ex(rsa, bits, ret, NULL); 
    printf("Estado del RSA_generate_key_ex: %i\n", statekey);
    BN_free(ret); 
    RSA_free(rsa);  
    return 0;
}
