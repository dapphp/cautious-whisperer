#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <openssl/rand.h>

// done
char table[] = " !\"#$%&'()*+,-./0123456789:;=?@ABCDEFGHIJLKMNOPQRSTUVWXYZ\\_abcdefghijlkmnopqrstuvwxyz";

char testPlaintext1[]  = "Red hawk to fly the coop at zero dark thirty. Negative intercept.";
char testKey1[]        = "qkBa4WYA 8HgAPOQaie(Q EwoO8Ge$-u00:/@C$nQBqJ%Iy;,!QVUll//,4i3H!Se$b%u/92tNP S7x8_d9x2;,_g$C9B!eh'X+tk6BV,D%F(2+tk;MG;giEKJ7((";
char testCiphertext1[] = "2333945986123601000211659515284737332608087308557304023747678952167885910033823814085323193927907760251931326982879083438001752777";

char testPlaintext2[]  = "Due to unforeseen circumstances we regretfully must send you this very long message. The message is exactly as long as a pad.";
char testKey2[]        = "YIiZVnUoIw5a9XYTU;taa_!rpo9cpCatiCEeWvdRPtJF-xG09)W5!3@#2a\"TeiB8wy5Ucv6362fFyFZuNB.,V+;PlGGZ%dnGs1MBq+\"hxKNbY4/EYN.Aw6(\"Dhe\\Y";
char testCiphertext2[] = "8918305630455152114594358831181323273926351980475151843335963678489635391645381124421905826537870486312178820265184275296345989158830114376322889590293654993356039777265261930969080033822137007784203238936127601127601497150428167931409908613440221969";

char testPlaintext3[]  = "Today on this day, nothing happened.";
char testKey3[]        = "t-mDQaR3z'/;iJLsOKl&'Yf:TXcrD%$x.4.tuVps=Oh0pJ8Y@Z\\eDBk$?4BupPTIeaajDHJGr4'7+NSvSgsB\\t;v(OdJ\".Y3uVHmgsN,b761cQ#!\\!p;\"'vTqL\"v2";
char testCiphertext3[] = "288633933059219184858194444003362854697880333093221961429379784586837692";

// done
int charToCode(int c)
{
    int code = 0;
    for (int i = 0; i < strlen(table); ++i) {
        if (c == table[i]) {
            code = i;
            break;
        }
    }

    return code;
}

// done
int codeToChar(int c)
{
    return table[c];
}

// done
unsigned char *create_pad_page(ssize_t characters)
{
    char *page  = malloc(characters);
    char *bytes = malloc(characters);
    int  ret, tmp;

    ret = RAND_bytes(bytes, characters);
    if (ret == 0) {
        printf("Error getting random bytes\n");
        exit(2);
    } else if (ret == -1) {
        printf("Random bytes not supported\n");
        exit(2);
    }

    for (int i = 0; i < characters; ++i) {
        tmp     = bytes[i];
        page[i] = table[tmp % strlen(table)];
    }

    free(bytes);

    return page;
}

// done
unsigned char *encrypt_message(const char *message, const char *page)
{
    size_t length;
    char *ciphertext;
    int tmp;

    length     = strlen(message);
    ciphertext = malloc(length * 2 + 1);
    if (ciphertext == NULL) {
        printf("Failed to allocate memory for message\n");
        exit(2);
    }

    for (int i = 0; i < length; ++i) {
        if (message[i] == '\n') break;
        tmp = ((charToCode(message[i]) + charToCode(page[i]))) % 100;
        sprintf(ciphertext + (i * 2), "%02d", tmp);
    }

    return ciphertext;
}

unsigned char *format_ciphertext(const char *ciphertext)
{
    char *buffer = malloc(strlen(ciphertext) * 2.5);
    memset(buffer, 0, strlen(ciphertext) * 2.5);

    for (int i = 0, p = 0; i < strlen(ciphertext); ++i, ++p) {
        if (i > 0 && i % 5 == 0) {
            buffer[p++] = ' ';
        }

        sprintf(buffer + p, "%c", ciphertext[i]);
    }

    return buffer;
}

unsigned char *decrypt_ciphertext(const char *ciphertext, const char *page)
{
    unsigned char *decrypted;
    size_t message_length = strlen(ciphertext);
    size_t length         = (message_length / 2) + 1;
    char buf[3];
    int  tmp, tmp2;

#ifndef NDEBUG
    assert(message_length % 2 == 0);
#endif

    decrypted = malloc(length);
    if (decrypted == NULL) {
        printf("Failed to allocate memory for decrypted message\n");
        exit(2);
    }

    memset(decrypted, 0, length);

    for (int i = 0; i < message_length; i += 2) {
        buf[0]   = ciphertext[i];
        buf[1]   = ciphertext[i + 1];
        buf[2]   = 0;

        tmp  = (int)strtol(buf, NULL, 10);
        tmp2 = charToCode(page[i / 2]);
        tmp -= tmp2;
        if (tmp < 0) {
            tmp += 100;
        }

        decrypted[i / 2] = codeToChar(tmp);
    }

    return decrypted;
}

void verify(char *ciphertext, char *key, char *plaintext)
{

    char *encrypted = encrypt_message(plaintext, key);
    char *decrypted = decrypt_ciphertext(ciphertext, key);
    char *formatted = format_ciphertext(ciphertext);

    printf("Plaintext = %s\n", plaintext);
    printf("Key       = %s\n", key);
    printf("Expect CT = %s\n", ciphertext);
    printf("Actual CT = %s\n", encrypted);
    printf("Decrypted = %s\n", decrypted);
    printf("Formatted = %s\n", formatted);
    printf("\n\n");

    free(encrypted);
    free(formatted);
    free(decrypted);
}

int main()
{
    ssize_t len      = 125;
    char *page;
    char *message    = malloc(len + 1);
    char *ciphertext;
    char *formatted;
    char *decrypted;

    verify(testCiphertext1, testKey1, testPlaintext1);
    verify(testCiphertext2, testKey2, testPlaintext2);
    verify(testCiphertext3, testKey3, testPlaintext3);

    page = create_pad_page(len);

    printf("Random Key = %s\n\n", page);

    printf("Enter message to encrypt: ");
    getline(&message, &len, stdin);

    ciphertext = encrypt_message(message, page);
    formatted  = format_ciphertext(ciphertext);

    printf("\nCiphertext = %s\n", formatted);

    memset(ciphertext, 0, strlen(ciphertext));

    for (int i = 0, p = 0; i < strlen(formatted); ++i, ++p) {
        if (formatted[p] == ' ') {
            i--;
            continue;
        }
        ciphertext[i] = formatted[p];
    }

    printf("\nStripped Ciphertext = %s\n", ciphertext);

    decrypted = decrypt_ciphertext(ciphertext, page);

    printf("Decrypted Ciphertext = %s\n", decrypted);
}
