#include <readpassphrase.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>

#include "misc.h"
#include "ncod.h"

int main(int argc, char *argv[]) {
    if (sodium_init() != 0) {
        ERROR("failed to initialize libsodium\n");
        return -1;
    }

    int ch;
    char *filename = "ncod.db";
    enum { NONE, GET, STORE, INIT } action = NONE;
    while ((ch = getopt(argc, argv, "is:g:f:")) != -1) {
        switch (ch) {
        case 'i':
            action = INIT;
            break;
        case 's':
            action = STORE;
            break;
        case 'g':
            action = GET;
            break;
        case 'f':
            filename = optarg;
            break;
        case '?':
        default:
            usage();
            return -1;
        }
    }

    switch (action) {
    case GET:
        return get_secret(filename);
        break;
    case STORE:
        return store_secret(filename);
        break;
    case INIT:
        return init_storage(filename);
        break;
    default:
        usage();
        return -1;
    }

    return 0;
}

void usage() {
    ERROR("Usage:\n"
          "ncod -i [-f FILE]\t\tInit secret storage\n"
          "ncod -g ID [ -f FILE]\t\tGet secret\n"
          "ncod -s ID [ -f FILE]\t\tStore secret\n");
}

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

int init_storage(char *filename) {
    int result = 0;
    unsigned char *key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    unsigned char *storage = (unsigned char *)sodium_malloc(STORAGE_BYTES);
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    if (key == NULL || storage == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }

    if (derive_key(key, salt, nonce, NULL, 1) != 0) {
        ERROR("cannot read password\n");
        result = -1;
        goto init_cleanup;
    }

    sodium_memzero(storage, STORAGE_LEN);
    result = save_storage(filename, salt, nonce, key, storage);
    if (result == 0) {
        printf("Initialized secret storage in %s\n", filename);
    }

init_cleanup:
    sodium_memzero(storage, STORAGE_BYTES);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(key);
    sodium_free(storage);

    return result;
}

int store_secret(char *filename) {
    int result = 0;
    unsigned char *key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    unsigned char *storage = (unsigned char *)sodium_malloc(STORAGE_BYTES);
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    if (key == NULL || storage == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }
    FILE *file = fopen(filename, "r+b");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        return -1;
    }

    if (derive_key(key, salt, nonce, file, 0) != 0) {
        ERROR("cannot read password\n");
        result = -1;
        goto store_cleanup;
    }

    if (crypto_secretbox_open_easy(storage, ciphertext, CIPHER_BYTES, nonce, key) != 0) {
        ERROR("Cannot decode container\n");
        result = -1;
        goto decode_cleanup;
    };

    sodium_memzero(storage, STORAGE_LEN);
    result = save_storage(filename, salt, nonce, key, storage);
    if (result == 0) {
        printf("Initialized secret storage in %s\n", filename);
    }

store_cleanup:
    sodium_memzero(storage, STORAGE_BYTES);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(key);
    sodium_free(storage);

    return result;
}

int save_storage(unsigned char *filename, unsigned char *salt, unsigned char *nonce, unsigned char *key,
                 unsigned char *storage) {
    int result = 0;
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        return -1;
    }
    unsigned char *ciphertext = (unsigned char *)sodium_malloc(CIPHER_BYTES);
    if (ciphertext == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }
    // write header
    if (fwrite(salt, sizeof(salt), 1, file) != 1) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto save_cleanup;
    }
    if (fwrite(nonce, sizeof(nonce), 1, file) != 1) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto save_cleanup;
    }
    crypto_secretbox_easy(ciphertext, storage, STORAGE_BYTES, nonce, key);
    if (fwrite(ciphertext, CIPHER_BYTES, 1, file) != 1) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto save_cleanup;
    }
save_cleanup:
    if (fclose(file) != 0) {
        ERROR("Cannot close file: %s", strerror(errno));
        result = -1;
    }
    sodium_free(ciphertext);
    return result;
}

int get_secret(char *filename) {
    int result = 0;
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        return -1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char *key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    unsigned char *ciphertext = (unsigned char *)sodium_malloc(CIPHER_BYTES);
    unsigned char *msg = (unsigned char *)sodium_malloc(STORAGE_BYTES);
    if (key == NULL || ciphertext == NULL || msg == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }

    if (derive_key(key, salt, nonce, file, 0) != 0) {
        ERROR("cannot read password\n");
        result = -1;
        goto decode_cleanup;
    }
    if (fread(ciphertext, CIPHER_BYTES, 1, file) < 0) {
        ERROR("cannot read container\n");
        result = -1;
        goto decode_cleanup;
    }

    if (crypto_secretbox_open_easy(msg, ciphertext, CIPHER_BYTES, nonce, key) != 0) {
        ERROR("Cannot decode container\n");
        result = -1;
        goto decode_cleanup;
    };

    dump(msg, STORAGE_BYTES);

decode_cleanup:
    sodium_memzero(msg, STORAGE_BYTES);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(key);
    sodium_free(msg);
    sodium_free(ciphertext);

    return result;
}
