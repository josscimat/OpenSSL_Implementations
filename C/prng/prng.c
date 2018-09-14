/* gcc prng.c -o prng -pthread -lcrypto -ldl -static-libgcc -I/usr/local/openssl/include -L/usr/local/openssl/lib /usr/local/openssl/lib/libcrypto.a /usr/local/openssl/lib/libssl.a */

#include <stdio.h>
#include <openssl/rand.h>

int main()
{
    const void *buf; 
    int num = 4294967295; 
    double entropy; 
    RAND_add(&buf, num, entropy); 
    printf("El valor del buffer random es: %llx\n", (unsigned long long int) buf);
    return 0;
}
