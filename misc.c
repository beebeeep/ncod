#include "misc.h"

#include <readpassphrase.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

// derive_key asks user for password and derives encryption key, salt and nonce from it.
// writes results to provided pre-allocated buffers
// if container file is not NULL, password salt and encryption nonce will be read from file, otherwise - generated
// if confirm_pw is non-zero, password will be asked twice
int derive_key(unsigned char *key, unsigned char *pw_salt, unsigned char *nonce, FILE *container, int confirm_pw) {
    int result = 0;
    unsigned char *pw = (unsigned char *)sodium_malloc(PW_LEN);
    if (pw == NULL) {
        ERROR("cannot allocate memory\n");
        return -1;
    }
    unsigned char *pw2 = NULL;
    if (confirm_pw) {
        pw2 = (unsigned char *)sodium_malloc(PW_LEN);
        if (pw2 == NULL) {
            ERROR("cannot allocate memory\n");
            goto cleanup;
        }
    }

    sodium_memzero(pw, PW_LEN);
    for (int i = 0; i < (confirm_pw ? 3 : 1); i++) {
        readpassphrase("Password: ", (char *)pw, PW_LEN, 0);
        if (!confirm_pw) {
            goto pw_ok;
        }
        readpassphrase("Repeat password: ", (char *)pw2, PW_LEN, 0);
        if (strncmp((char *)pw, (char *)pw2, PW_LEN) != 0) {
            ERROR("password does not match, try again\n");
        } else {
            goto pw_ok;
        }
    }
    result = -1;
    goto cleanup;

pw_ok:
    if (container == NULL) {
        randombytes_buf(pw_salt, crypto_pwhash_SALTBYTES);
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    } else {
        fseek(container, 0, SEEK_SET);
        if (fread(pw_salt, crypto_pwhash_SALTBYTES, 1, container) < 0) {
            ERROR("cannot read container\n");
            result = -1;
            goto cleanup;
        }
        if (fread(nonce, crypto_secretbox_NONCEBYTES, 1, container) < 0) {
            ERROR("cannot read container\n");
            result = -1;
            goto cleanup;
        }
    }
    if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, (char *)pw, PW_LEN, pw_salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        ERROR("Key derivation failed\n");
        result = -1;
    }

cleanup:
    sodium_memzero(pw, PW_LEN);
    sodium_free(pw);
    if (pw2 != NULL) {
        sodium_memzero(pw2, PW_LEN);
        sodium_free(pw2);
    }
    return result;
}