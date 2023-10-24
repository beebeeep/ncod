#ifndef NCOD_H
#define NCOD_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define ERROR(...) (fprintf(stderr, __VA_ARGS__))

#define STORAGE_LEN 1000
#define STORAGE_BYTES (sizeof(secretRecord) * STORAGE_LEN)
#define CIPHER_BYTES (STORAGE_BYTES + crypto_secretbox_MACBYTES)
#define ID_LEN 32
#define USER_LEN 64
#define SECRET_LEN 512

typedef struct {
    time_t last_updated;
    char id[ID_LEN + 1];
    char user[USER_LEN + 1];
    char secret[SECRET_LEN + 1];
} secretRecord;

// declare all used memory as globals to simplify tracking of its lifecycle,
// especially secret data
// non-secret data
unsigned char salt[crypto_pwhash_SALTBYTES];
unsigned char nonce[crypto_secretbox_NONCEBYTES];
unsigned char ciphertext[CIPHER_BYTES];
// secret data
unsigned char *key;
unsigned char *storage;
unsigned char *pw;
unsigned char *pw2;

int derive_key(FILE *container, int confirm_pw);
int store_secret(char *secret_id, char *filename);
int get_secret(char *secret_id, char *filename);
int init_storage(char *filename);
void dump(unsigned char *d, size_t l);
void usage();

#endif