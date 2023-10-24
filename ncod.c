#include <readpassphrase.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <time.h>
#include <unistd.h>

#include "ncod.h"

int main(int argc, char *argv[]) {
    if (sodium_init() != 0) {
        ERROR("failed to initialize libsodium\n");
        return -1;
    }

    key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    storage = (unsigned char *)sodium_malloc(STORAGE_BYTES);
    pw = (unsigned char *)sodium_malloc(SECRET_LEN);
    pw2 = (unsigned char *)sodium_malloc(SECRET_LEN);
    if (key == NULL || storage == NULL || pw == NULL || pw2 == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }

    int ch;
    char *filename = "ncod.db";
    char secret_id[ID_LEN];
    enum { NONE, GET, STORE, INIT } action = NONE;
    while ((ch = getopt(argc, argv, "is:g:f:")) != -1) {
        switch (ch) {
        case 'i':
            action = INIT;
            break;
        case 's':
            action = STORE;
            strncpy(secret_id, optarg, ID_LEN);
            break;
        case 'g':
            action = GET;
            strncpy(secret_id, optarg, ID_LEN);
            break;
        case 'f':
            filename = (char *)malloc(strlen(optarg));
            if (filename == NULL) {
                ERROR("cannot allocate memory\n");
                return -1;
            }
            strncpy(filename, optarg, strlen(optarg));
            break;
        case '?':
        default:
            usage();
            return -1;
        }
    }

    switch (action) {
    case GET:
        return get_secret(secret_id, filename);
        break;
    case STORE:
        return store_secret(secret_id, filename);
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

// derive_key asks user for password and derives encryption key, salt and nonce from it.
// writes results to provided pre-allocated buffers
// if container file is not NULL, password salt and encryption nonce will be read from file, otherwise - generated
// if confirm_pw is non-zero, password will be asked twice
int derive_key(FILE *container, int confirm_pw) {
    read_password(confirm_pw ? 3 : 1);

    if (container == NULL) {
        randombytes_buf(salt, crypto_pwhash_SALTBYTES);
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    } else {
        fseek(container, 0, SEEK_SET);
        if (fread(salt, crypto_pwhash_SALTBYTES, 1, container) != 1) {
            ERROR("cannot read container\n");
            return -1;
        }
        if (fread(nonce, crypto_secretbox_NONCEBYTES, 1, container) != 1) {
            ERROR("cannot read container\n");
            return -1;
        }
    }

    if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, (char *)pw, SECRET_LEN, salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        ERROR("Key derivation failed\n");
        return -1;
    }

    return 0;
}

int read_password(int attempts) {
    int result = -1;
    sodium_memzero(pw, SECRET_LEN);
    sodium_memzero(pw2, SECRET_LEN);

    for (int i = 0; i < attempts; i++) {
        readpassphrase("Password: ", (char *)pw, SECRET_LEN, 0);
        if (attempts == 1) {
            return 0;
        }
        readpassphrase("Repeat password: ", (char *)pw2, SECRET_LEN, 0);
        if (strncmp((char *)pw, (char *)pw2, SECRET_LEN) != 0) {
            ERROR("password does not match, try again\n");
        } else {
            result = 0;
            break;
        }
    }

    sodium_memzero(pw2, SECRET_LEN);
    return result;
}

int init_storage(char *filename) {
    if (derive_key(NULL, 1) != 0) {
        ERROR("cannot read password\n");
        return -1;
    }

    sodium_memzero(storage, STORAGE_LEN);
    if (save_storage(filename) == 0) {
        printf("Initialized secret storage in %s\n", filename);
        return 0;
    }
    ERROR("failed to initialize secret storage in %s\n", filename);
    return -1;
}

int store_secret(char *secret_id, char *filename) {
    if (read_storage(filename) != 0) {
        ERROR("Cannot read storage\n");
        return -1;
    }

    // find next empty slot for storage
    secretRecord *secrets = (secretRecord *)storage;
    int idx = -1;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (secrets[i].id[0] = '\0') {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        ERROR("no more space for secrets :(\n");
        return -1;
    }

    char *user = malloc(USER_LEN);
    size_t userlen = USER_LEN;
    if (getline(&user, &userlen, stdin) == -1) {
        ERROR("cannot get username\n");
        return -1;
    }
    user[strlen(user) - 1] = '\0';
    if (strlen(user) > USER_LEN) {
        ERROR("too long username\n");
        return -1;
    }
    if (read_password(3) != 0) {
        ERROR("cannot get password\n");
    }

    strncpy(secrets[idx].id, secret_id, ID_LEN);
    strncpy(secrets[idx].user, user, USER_LEN);
    strncpy(secrets[idx].secret, pw, SECRET_LEN);
    secrets[idx].last_updated = time(NULL);

    return save_storage(filename);
}

int read_storage(unsigned char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        return -1;
    }

    if (derive_key(file, 0) != 0) {
        ERROR("cannot read password\n");
        return -1;
    }
    if (fread(ciphertext, CIPHER_BYTES, 1, file) < 0) {
        ERROR("cannot read container\n");
        return -1;
    }
    fseek(file, sizeof(salt) + sizeof(nonce), SEEK_SET);

    if (crypto_secretbox_open_easy(storage, ciphertext, CIPHER_BYTES, nonce, key) != 0) {
        ERROR("Cannot decode container\n");
        return -1;
    }

    if (fclose(file) != 0) {
        ERROR("Cannot close file: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int save_storage(unsigned char *filename) {
    if (key == NULL) {
        ERROR("Storage is not opened");
        return -1;
    }

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        return -1;
    }

    // regenerate nonce before re-encoding storage, never reuse nonce
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    // write header
    if (fwrite(salt, sizeof(salt), 1, file) != 1) {
        ERROR("Cannot write to %s", filename);
        return -1;
    }
    if (fwrite(nonce, sizeof(nonce), 1, file) != 1) {
        ERROR("Cannot write to %s", filename);
        return -1;
    }

    // encode storage and write it to the file
    crypto_secretbox_easy(ciphertext, storage, STORAGE_BYTES, nonce, key);
    if (fwrite(ciphertext, CIPHER_BYTES, 1, file) != 1) {
        ERROR("Cannot write to %s", filename);
        return -1;
    }

    if (fclose(file) != 0) {
        ERROR("Cannot close file: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int get_secret(char *secret_id, char *filename) {
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

    dump(msg, STORAGE_BYTES);

decode_cleanup:
    sodium_memzero(msg, STORAGE_BYTES);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(key);
    sodium_free(msg);
    sodium_free(ciphertext);

    return result;
}
