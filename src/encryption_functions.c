#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_BITS 128

const char malloc_failed[] = "Malloc failed";


int pbkdf2_test(char *pass, int passlen, unsigned char **in)
{
    int ret = 0;
    unsigned char *salt;
    int key_length = KEY_BITS / 8;

    printf("Your password = %s and is %d bytes long\n", pass, passlen);

    do {
        salt = malloc(SALT_LEN);
        if (salt == NULL) {
            printf("%s\n", malloc_failed);
            break;
        }

        *in = malloc(key_length);
        if (*in == NULL) {
            printf("Failed to allocate memory for key\n");
            break;
        }

        if (RAND_bytes(salt, 8) != 1) {
            ERR_print_errors_fp(stderr);
            break;
        }

        printf("Salt = %.8s\n", salt);

        if ((ret = PKCS5_PBKDF2_HMAC(pass, passlen, salt, SALT_LEN, PBKDF2_ITERATIONS, EVP_sha256(), key_length, *in)) == 0) {
            ERR_print_errors_fp(stderr);
            free(*in);
            break;
        }

        printf("Your key (from c)        = %.16s\n", *in);
    } while(0);

    if (salt != NULL) {
        free(salt);
    }

    return ret;
}
