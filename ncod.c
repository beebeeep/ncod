// vim: tw=120
#include <stdio.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>
#include <readpassphrase.h>

#include <sodium.h>

#define ERROR(...) (fprintf(stderr, __VA_ARGS__))

#define MOD_ENCODE 1
#define MOD_DECODE 2
#define PW_LEN 33
#define STORAGE_LEN 64
#define CIPHER_LEN (STORAGE_LEN + crypto_secretbox_MACBYTES)

int encode(char *filename);
int decode(char *filename);

int main(int argc, char *argv[]) {
    if (sodium_init() != 0) {
        ERROR("failed to initialize libsodium\n");
        return -1;
    }

    int ch;
    while ((ch = getopt(argc, argv, "ed")) != -1) {
        switch (ch) {
            case 'e': 
                return encode(argv[optind]);
                break;
            case 'd':
                return decode(argv[optind]);
                break;
            case '?':
            default:
                ERROR("Usage:\nncod -e FILE\t\tEncode stdin to file\nncod -d FILE\t\tDecode file to stdin\n");
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


    int i;
    for (i = 0; i < 3; i++) {
        readpassphrase("Password: ", (char *)pw1, PW_LEN, 0);
        readpassphrase("Repeat password: ", (char *)pw2, PW_LEN, 0);
        if (strncmp((char *)pw1, (char *)pw2, PW_LEN) != 0) {
            ERROR("password does not match, try again\n");
        } else {
            goto encode_pw_ok;
        }
    }
    ERROR("cannot read password\n");
    result = -1;
    goto encode_cleanup;

encode_pw_ok:
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    if(crypto_pwhash(key, crypto_secretbox_KEYBYTES, (char *)pw1, PW_LEN, salt, 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        ERROR("Key derivation failed\n");
        result = -1;
        goto encode_cleanup;
    }
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        ERROR("Cannot open %s: %s", filename, strerror(errno));
        result = -1;
        goto encode_cleanup;
    }

    // write header
    if (fwrite(salt, crypto_pwhash_SALTBYTES, 1, file) < 0) {
        ERROR("Cannot write to %s", filename);
        result = -1;
        goto encode_cleanup;
    }
    if (fwrite(nonce, crypto_secretbox_NONCEBYTES, 1, file) < 0) {
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
    sodium_memzero(ciphertext, CIPHER_LEN);
    sodium_free(pw1);
    sodium_free(pw2);
    sodium_free(key);
    sodium_free(msg);
    sodium_free(ciphertext);

    return result; 
}

int decode(char *filename) {
    ERROR("not implemented\n");
    return -1;
}

