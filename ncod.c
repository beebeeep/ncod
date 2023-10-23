#include <readpassphrase.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>

#include "misc.h"

#define MOD_ENCODE 1
#define MOD_DECODE 2
#define STORAGE_LEN 64
#define CIPHER_LEN (STORAGE_LEN + crypto_secretbox_MACBYTES)
#define ID_LEN 32
#define USER_LEN 64
#define SECRET_LEN 512

int encode(char *filename);
int decode(char *filename);

typedef struct {
    time_t last_updated;
    char id[ID_LEN];
    char user[USER_LEN];
    char secret[SECRET_LEN];
} secretRecord;

void dump(unsigned char *d, size_t l) {
    for (size_t i = 0; i < l; i++) {
        printf("%x ", d[i]);
        if (i != 0 && i % 16 == 15) {
            printf("\n");
        } else if (i != 0 && i % 16 == 7) {
            printf(" ");
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (sodium_init() != 0) {
        ERROR("failed to initialize libsodium\n");
        return -1;
    }

    int ch;
    while ((ch = getopt(argc, argv, "ied")) != -1) {
        switch (ch) {
        case 'e':
            return encode(argv[optind]);
            break;
        case 'd':
            return decode(argv[optind]);
            break;
        case '?':
        default:
            ERROR("Usage:\nncod -e FILE\t\tEncode stdin to file\nncod -d "
                  "FILE\t\tDecode file to stdin\n");
            return -1;
        }
    }

    return 0;
}

int encode(char *filename) {
    int result = 0;
    unsigned char *pw1 = (unsigned char *)sodium_malloc(PW_LEN);
    unsigned char *pw2 = (unsigned char *)sodium_malloc(PW_LEN);
    unsigned char *key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    unsigned char *ciphertext = (unsigned char *)sodium_malloc(CIPHER_LEN);
    unsigned char *msg = (unsigned char *)sodium_malloc(STORAGE_LEN);
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    if (pw1 == NULL || pw2 == NULL || key == NULL || ciphertext == NULL || msg == NULL) {
        ERROR("cannot allocate memory\n");
    }

    if (derive_key(key, salt, nonce, NULL, 1) != 0) {
        ERROR("cannot read password\n");
        result = -1;
        goto encode_cleanup;
    }

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        result = -1;
        goto encode_cleanup;
    }

    // write header
    if (fwrite(salt, sizeof(salt), 1, file) < 0) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto encode_cleanup;
    }
    if (fwrite(nonce, sizeof(nonce), 1, file) < 0) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto encode_cleanup;
    }

    // read input, encode it and write to the file
    if (fread(msg, STORAGE_LEN, 1, stdin) < 1) {
        ERROR("cannot read input\n");
        result = -1;
        goto encode_cleanup;
    }
    crypto_secretbox_easy(ciphertext, msg, STORAGE_LEN, nonce, key);
    if (fwrite(ciphertext, CIPHER_LEN, 1, file) < 0) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto encode_cleanup;
    }
    if (fclose(file) != 0) {
        ERROR("Cannot close file: %s", strerror(errno));
        result = -1;
        goto encode_cleanup;
    }

encode_cleanup:
    sodium_memzero(pw1, PW_LEN);
    sodium_memzero(pw2, PW_LEN);
    sodium_memzero(msg, STORAGE_LEN);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(pw1);
    sodium_free(pw2);
    sodium_free(key);
    sodium_free(msg);
    sodium_free(ciphertext);

    return result;
}

int decode(char *filename) {
    int result = 0;
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        return -1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char *pw = (unsigned char *)sodium_malloc(PW_LEN);
    unsigned char *key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    unsigned char *ciphertext = (unsigned char *)sodium_malloc(CIPHER_LEN);
    unsigned char *msg = (unsigned char *)sodium_malloc(STORAGE_LEN);
    if (derive_key(key, salt, nonce, file, 0) != 0) {
        ERROR("cannot read password\n");
        result = -1;
        goto decode_cleanup;
    }
    if (fread(ciphertext, CIPHER_LEN, 1, file) < 0) {
        ERROR("cannot read container\n");
        result = -1;
        goto decode_cleanup;
    }

    if (crypto_secretbox_open_easy(msg, ciphertext, CIPHER_LEN, nonce, key) != 0) {
        ERROR("Cannot decode container\n");
        result = -1;
        goto decode_cleanup;
    };

    dump(msg, STORAGE_LEN);

decode_cleanup:
    sodium_memzero(pw, PW_LEN);
    sodium_memzero(msg, STORAGE_LEN);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(pw);
    sodium_free(key);
    sodium_free(msg);
    sodium_free(ciphertext);

    return result;
}
