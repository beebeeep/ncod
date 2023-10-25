#ifdef LINUX
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif
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
    char *filename = malloc(256);
    if (key == NULL || storage == NULL || pw == NULL || pw2 == NULL || filename == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }

    int ch;
    snprintf(filename, 256, "%s/.ncod.db", getenv("HOME"));
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
            filename = (char *)realloc(filename, strlen(optarg));
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

    int result;
    switch (action) {
    case GET:
        result = get_secret(secret_id, filename);
        break;
    case STORE:
        result = store_secret(secret_id, filename);
        break;
    case INIT:
        result = init_storage(filename);
        break;
    default:
        usage();
        result = -1;
    }

    // securely erase all secret data and free the memory
    sodium_memzero(pw, SECRET_LEN);
    sodium_memzero(pw2, SECRET_LEN);
    sodium_memzero(storage, STORAGE_BYTES);
    sodium_memzero(key, crypto_secretbox_KEYBYTES);
    sodium_free(pw);
    sodium_free(pw2);
    sodium_free(storage);
    sodium_free(key);

    return result;
}

void usage() {
    ERROR("Usage:\n"
          "ncod -i [-f FILE]\t\tInit secret storage\n"
          "ncod -g ID [ -f FILE]\t\tGet secret\n"
          "ncod -s ID [ -f FILE]\t\tStore secret\n");
}

// derive_key asks user for password and derives encryption key, salt and nonce from it.
// writes results to globals "key", "nonce", "salt"
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

// read_password reads password from user
// if attempts > 1 then it asks user to repeat the password, giving them several attempts
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

// init_storage initializes empty secret storage
// file will be overwritten
int init_storage(char *filename) {
    printf("Initializing secret storage in %s\n", filename);
    if (derive_key(NULL, 1) != 0) {
        ERROR("cannot read password\n");
        return -1;
    }

    sodium_memzero(storage, STORAGE_LEN);
    if (save_storage(filename) == 0) {
        printf("Storage initialized.\n");
        return 0;
    }
    ERROR("failed to initialize secret storage in %s\n", filename);
    return -1;
}

// get_secret finds secret by its ID and prints it to stdout
int get_secret(char *secret_id, char *filename) {
    if (read_storage(filename) != 0) {
        ERROR("Cannot read storage\n");
        return -1;
    }

    secretRecord *secrets = (secretRecord *)storage;
    int idx = -1;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (strncmp(secret_id, secrets[i].id, ID_LEN) == 0) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        ERROR("secret not found");
        return -1;
    }
    printf("User: %s\nPassword: %s\n", secrets[idx].user, secrets[idx].secret);
    return 0;
}

// store_secret asks for username and password and saves them into free cell in storage
int store_secret(char *secret_id, char *filename) {
    if (read_storage(filename) != 0) {
        ERROR("Cannot read storage\n");
        return -1;
    }

    // find next empty slot for storage
    secretRecord *secrets = (secretRecord *)storage;
    int idx = -1;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (secrets[i].id[0] == '\0') {
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
    printf("Username: ");
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
    strncpy(secrets[idx].secret, (char *)pw, SECRET_LEN);
    secrets[idx].last_updated = time(NULL);

    return save_storage(filename);
}

// read storage decrypts the storage contents from file
// storage contents will be in "storage" variable, also it sets "key" and "salt" variables
int read_storage(char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s\n", filename, strerror(errno));
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
        ERROR("Cannot close file: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

// save_storage encrypts contents of "storage" variable using the key in "key" variable
// encryption nonce from "nonce" is regenerated, password salt in "salt" is reused
int save_storage(char *filename) {
    if (key == NULL) {
        ERROR("Storage is not opened");
        return -1;
    }

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s\n", filename, strerror(errno));
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
        ERROR("Cannot close file: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
