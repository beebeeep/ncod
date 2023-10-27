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
#define IMPORT_FMT "%32s %64s %512s\n"

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
secretRecord *tmp_record;

int derive_key(FILE *container, int confirm_pw);
int store_secret(char *secret_id, char *filename, int overwrite);
int get_secret(char *secret_id, char *filename);
int delete_secret(char *secret_id, char *filename);
int list_secrets(char *filename);
int init_storage(char *filename);
int read_password(char *prompt, int attempts);
int read_storage(char *filename);
int save_storage(char *filename);
int export_secrets(char *filename);
int import_secrets(FILE *src, char *filename);
secretRecord *find_secret(char *secret_id);
char *get_input(char *prompt);
void usage();

#endif