#ifdef LINUX
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#ifdef BSD
#include <errno.h>
#else
#include <sys/errno.h>
#endif
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ncod.h"

int main(int argc, char *argv[]) {
    if (sodium_init() != 0) {
        STDERR("Failed to initialize libsodium\n");
        return -1;
    }

    key = (unsigned char *)sodium_malloc(crypto_secretbox_KEYBYTES);
    storage = (unsigned char *)sodium_malloc(STORAGE_BYTES);
    pw = (unsigned char *)sodium_malloc(SECRET_LEN);
    pw2 = (unsigned char *)sodium_malloc(SECRET_LEN);
    tmp_record = (secretRecord *)sodium_malloc(sizeof(secretRecord));
    char *filename = malloc(256);
    FILE *import_file;
    if (key == NULL || storage == NULL || pw == NULL || pw2 == NULL || filename == NULL) {
        STDERR("Cannot allocate memory\n");
        return -1;
    }

    int ch;
#ifdef DEBUG
    snprintf(filename, 256, "./ncod.db");
#else
    snprintf(filename, 256, "%s/.ncod.db", getenv("HOME"));
#endif

    char secret_id[ID_LEN];
    enum { NONE, GET, STORE, UPDATE, DELETE, LIST, INIT, EXPORT, IMPORT } action = NONE;
    int pipe_pw = 0;
    while ((ch = getopt(argc, argv, "hielcm:s:g:u:d:f:")) != -1) {
        switch (ch) {
        case 'i':
            action = INIT;
            break;
        case 'l':
            action = LIST;
            break;
        case 'c':
            pipe_pw = 1;
            break;
        case 'e':
            action = EXPORT;
            break;
        case 'm':
            action = IMPORT;
            import_file = fopen(optarg, "r");
            if (import_file == NULL) {
                STDERR("Cannot open %s: %s", optarg, strerror(errno));
                return -1;
            }
            break;
        case 's':
            action = STORE;
            strncpy(secret_id, optarg, ID_LEN);
            break;
        case 'g':
            action = GET;
            strncpy(secret_id, optarg, ID_LEN);
            break;
        case 'u':
            action = UPDATE;
            strncpy(secret_id, optarg, ID_LEN);
            break;
        case 'd':
            action = DELETE;
            strncpy(secret_id, optarg, ID_LEN);
            break;
        case 'f':
            filename = (char *)realloc(filename, strlen(optarg));
            if (filename == NULL) {
                STDERR("Cannot allocate memory\n");
                return -1;
            }
            strncpy(filename, optarg, strlen(optarg));
            break;
        case 'h':
        case '?':
        default:
            usage();
            return -1;
        }
    }

    int result;
    switch (action) {
    case NONE:
        result = fzf_secret(filename, pipe_pw);
        break;
    case GET:
        result = get_secret(secret_id, filename, pipe_pw);
        break;
    case STORE:
        result = store_secret(secret_id, filename, 0);
        break;
    case UPDATE:
        result = store_secret(secret_id, filename, 1);
        break;
    case DELETE:
        result = delete_secret(secret_id, filename);
        break;
    case INIT:
        result = init_storage(filename);
        break;
    case LIST:
        result = list_secrets(filename);
        break;
    case EXPORT:
        result = export_secrets(filename);
        break;
    case IMPORT:
        result = import_secrets(import_file, filename);
        fclose(import_file);
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
    sodium_memzero(tmp_record, sizeof(secretRecord));
    sodium_free(pw);
    sodium_free(pw2);
    sodium_free(storage);
    sodium_free(key);
    sodium_free(tmp_record);

    if (clean_clipboard != 0) {
        STDERR("Will clear the clipboard in 5 seconds (CTRL+c to cancel)... ");
        result = -1;
        sleep(5);
        result = copy_to_clipboard("********");
        STDERR("done.\n");
    }

    return result;
}

void usage() {
    STDERR("Usage:\n\n"
           "ncod [-c]                         Use fzf to find secret\n"
           "ncod -i [-f FILE]                 Init secret storage\n"
           "ncod [-c] -g ID [ -f FILE]        Get secret\n"
           "ncod -s ID [ -f FILE]             Store secret\n"
           "ncod -u ID [ -f FILE] .           Update secret\n"
           "ncod -d ID [ -f FILE]             Delete secret\n"
           "ncod -l [ -f FILE]                List all secrets\n"
           "ncod -e [ -f FILE]                Export all secrets\n"
           "ncod -m SECRETS_FILE [ -f FILE]   Import secrets\n");
}

// derive_key asks user for password and derives encryption key, salt and nonce from it.
// writes results to globals "key", "nonce", "salt"
// if container file is not NULL, password salt and encryption nonce will be read from file, otherwise - generated
// if confirm_pw is non-zero, password will be asked twice
int derive_key(FILE *container, int confirm_pw) {
    if (read_password("Storage password: ", confirm_pw ? 3 : 1) != 0) {
        return -1;
    }

    if (container == NULL) {
        randombytes_buf(salt, crypto_pwhash_SALTBYTES);
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    } else {
        fseek(container, 0, SEEK_SET);
        if (fread(salt, crypto_pwhash_SALTBYTES, 1, container) != 1) {
            STDERR("Cannot read container\n");
            return -1;
        }
        if (fread(nonce, crypto_secretbox_NONCEBYTES, 1, container) != 1) {
            STDERR("Cannot read container\n");
            return -1;
        }
    }

    if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, (char *)pw, SECRET_LEN, salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        STDERR("Key derivation failed\n");
        return -1;
    }

    return 0;
}

// read_password reads password from user
// if attempts > 1 then it asks user to repeat the password, giving them several attempts
int read_password(char *prompt, int attempts) {
#ifdef DEBUG
    strncpy((char *)pw, "secret", 7);
    return 0;
#else
    int result = -1;
    sodium_memzero(pw, SECRET_LEN);
    sodium_memzero(pw2, SECRET_LEN);

    for (int i = 0; i < attempts; i++) {
        readpassphrase(prompt, (char *)pw, SECRET_LEN, 0);
        if (attempts == 1) {
            return 0;
        }
        if (strlen((char *)pw) == 0) {
            STDERR("Empty password?\n");
            continue;
        }
        readpassphrase("Repeat password: ", (char *)pw2, SECRET_LEN, 0);
        if (strncmp((char *)pw, (char *)pw2, SECRET_LEN) != 0) {
            STDERR("Passwords do not match, try again\n");
        } else {
            result = 0;
            break;
        }
    }

    sodium_memzero(pw2, SECRET_LEN);
    return result;
#endif
}

// init_storage initializes empty secret storage
// will ask user to overwrite file if it exists
int init_storage(char *filename) {
    struct stat t;
    STDERR("Initializing secret storage in %s\n", filename);
    if (stat(filename, &t) == 0) {
        char *ans = get_input("Storage file already exists, overwrite (y/n)? ");
        if (ans != NULL && (ans[0] != 'y' && ans[0] != 'Y')) {
            free(ans);
            return -1;
        }
    }

    if (derive_key(NULL, 1) != 0) {
        STDERR("Cannot read password\n");
        return -1;
    }

    sodium_memzero(storage, STORAGE_BYTES);
    if (save_storage(filename) == 0) {
        return 0;
    }
    STDERR("Failed to initialize secret storage in %s\n", filename);
    return -1;
}

// get_secret finds secret by its ID and prints it to stdout
int get_secret(char *secret_id, char *filename, int pipe_pw) {
    if (filename != NULL) {
        if (read_storage(filename) != 0) {
            STDERR("Cannot read storage\n");
            return -1;
        }
    }

    secretRecord *record = find_secret(secret_id);
    if (record == NULL) {
        STDERR("Secret not found\n");
        return -1;
    }

    if (pipe_pw == 0) {
        printf("User: %s\nPassword: %s\n", record->user, record->secret);
    } else {
        if (copy_to_clipboard(record->secret) != 0) {
            return -1;
        }
        printf("User: %s\nPassword: (copied to clipboard)\n", record->user);
    }
    return 0;
}

// delete secret find secret by ID and deletes it from storage
int delete_secret(char *secret_id, char *filename) {
    if (read_storage(filename) != 0) {
        STDERR("Cannot read storage\n");
        return -1;
    }

    secretRecord *record = find_secret(secret_id);
    if (record == NULL) {
        STDERR("Secret not found");
        return -1;
    }

    memset(record, 0, sizeof(secretRecord));
    STDERR("Secret \"%s\" was deleted\n", secret_id);
    return save_storage(filename);
}

// list_secrets prints all secrets (only IDs and usernames) in storage
int list_secrets(char *filename) {
    if (read_storage(filename) != 0) {
        STDERR("Cannot read storage\n");
        return -1;
    }

    secretRecord *secrets = (secretRecord *)storage;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (secrets[i].last_updated != 0) {
            char updated[128];
            strftime(updated, 128, "%F %T", localtime(&secrets[i].last_updated));
            printf("ID: %s, user: %s, updated: %s\n", secrets[i].id, secrets[i].user, updated);
        }
    }
    return 0;
}

int export_secrets(char *filename) {
    if (read_storage(filename) != 0) {
        STDERR("Cannot read storage\n");
        return -1;
    }

    secretRecord *secrets = (secretRecord *)storage;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (secrets[i].last_updated != 0) {
            printf("%s %s %s\n", secrets[i].id, secrets[i].user, secrets[i].secret);
        }
    }
    return 0;
}

// import_secrets reads secrets from src and writes them to the storage
int import_secrets(FILE *src, char *filename) {
    if (read_storage(filename) != 0) {
        STDERR("Cannot read storage\n");
        return -1;
    }

    int count = 0;
    int n;
    int lineno = 1;
    for (;;) {
        // XXX fscanf is treating his input format in a pretty creative mode
        // so if anything is off with input line (wrong number of fields, incorrect length etc),
        // if may not fail immediately and consume some garbage
        n = fscanf(src, IMPORT_FMT, tmp_record->id, tmp_record->user, tmp_record->secret);
        if (n == EOF) {
            break;
        }
        if (n != 3) {
            STDERR("Incorrect file format at line %d, stopping import\n", lineno);
            break;
        }
        STDERR("Importing secret %s\n", tmp_record->id);
        lineno++;
        secretRecord *r = find_secret(tmp_record->id);
        if (r == NULL) {
            r = find_secret(NULL);
        }
        if (r == NULL) {
            STDERR("Too many secrets, stopping import\n");
            break;
        }
        count++;
        strncpy(r->id, tmp_record->id, ID_LEN);
        strncpy(r->user, tmp_record->user, USER_LEN);
        strncpy(r->secret, tmp_record->secret, SECRET_LEN);
        r->last_updated = time(NULL);
    }
    STDERR("Imported %d secrets\n", count);

    return save_storage(filename);
}

// store_secret asks for username and password and saves them into free cell in storage
// if there is secret with same ID, it will prompt user if they want to overwrite it, unless overwrite != 0
int store_secret(char *secret_id, char *filename, int overwrite) {
    if (read_storage(filename) != 0) {
        STDERR("Cannot read storage\n");
        return -1;
    }

    // find next empty slot for storage
    secretRecord *existing = find_secret(secret_id);
    secretRecord *vacant = find_secret(NULL);
    secretRecord *record = NULL;
    char *user_prompt = (char *)malloc(128);
    snprintf(user_prompt, 128, "Enter username: ");

    if (existing != NULL && overwrite) {
        snprintf(user_prompt, 128, "Enter username (leave empty to keep \"%s\"): ", existing->user);
        record = existing;
    } else if (existing != NULL && !overwrite) {
        char *ans = get_input("Secret already exists. Overwrite (y/n)? ");
        if (ans != NULL && (ans[0] == 'y' || ans[0] == 'Y')) {
            free(ans);
            snprintf(user_prompt, 128, "Enter username (leave empty to keep \"%s\"): ", existing->user);
            record = existing;
        }
    } else if (existing == NULL && vacant != NULL) {
        record = vacant;
    } else {
        STDERR("No more space for secrets :(\n)");
    }

    if (record == NULL) {
        STDERR("Password not stored.\n");
        return -1;
    }

    char *user = get_input(user_prompt);
    if (user == NULL) {
        STDERR("Cannot get username\n");
        return -1;
    }
    if (strlen(user) == 0) {
        if (existing != NULL) {
            // updating secret, keep user
            free(user);
            user = NULL;
        } else {
            STDERR("Empty username?\n");
            return -1;
        }
    }
    if (user != NULL && strlen(user) > USER_LEN) {
        STDERR("Too long username, max %d characters", USER_LEN);
        return -1;
    }

    if (read_password("Password: ", 3) != 0) {
        STDERR("Cannot get password\n");
    }

    strncpy(record->id, secret_id, ID_LEN);
    if (user != NULL) {
        strncpy(record->user, user, USER_LEN);
        free(user);
    }
    strncpy(record->secret, (char *)pw, SECRET_LEN);
    record->last_updated = time(NULL);

    free(user_prompt);
    return save_storage(filename);
}

// get_input prompts user to enter something from stdin. Input will be echoed.
// returns entered string (take care of freeing it) or NULL.
char *get_input(char *prompt) {
    char *result = malloc(USER_LEN);
    if (result == NULL) {
        STDERR("Cannot allocate memory.\n");
        return NULL;
    }
    STDERR("%s", prompt);
    size_t rsz = USER_LEN;
    if (getline(&result, &rsz, stdin) == -1) {
        STDERR("Cannot get input\n");
        return NULL;
    }
    result[strlen(result) - 1] = '\0';

    return result;
}

// find_secret returns index of secret in decoded storage.
// If secret_id == NULL, returns pointer to empty record,
// otherwise, returns pointer to record with matching ID.
// If nothing found, returns NULL
secretRecord *find_secret(char *secret_id) {
    secretRecord *secrets = (secretRecord *)storage;
    secretRecord *r = NULL;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (secret_id == NULL && secrets[i].id[0] == '\0') {
            r = &secrets[i];
            break;
        }
        if (secret_id != NULL && strncmp(secret_id, secrets[i].id, ID_LEN) == 0) {
            r = &secrets[i];
            break;
        }
    }
    return r;
}

// read storage decrypts the storage contents from file
// storage contents will be in "storage" variable, also it sets "key" and "salt" variables
int read_storage(char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        STDERR("Cannot open %s: %s\n", filename, strerror(errno));
        return -1;
    }

    if (derive_key(file, 0) != 0) {
        STDERR("Cannot read password\n");
        return -1;
    }
    if (fread(ciphertext, CIPHER_BYTES, 1, file) < 0) {
        STDERR("Cannot read container\n");
        return -1;
    }
    fseek(file, sizeof(salt) + sizeof(nonce), SEEK_SET);

    if (crypto_secretbox_open_easy(storage, ciphertext, CIPHER_BYTES, nonce, key) != 0) {
        STDERR("Cannot decode container\n");
        return -1;
    }

    if (fclose(file) != 0) {
        STDERR("Cannot close file: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// fzf_secret creates list of secrets and pipes it to fzf, allowing user to find desired ID
// note that fzf only gets IDs and usernames, actual password is returned by get_secret()
int fzf_secret(char *filename, int pipe_pw) {
    if (read_storage(filename) != 0) {
        STDERR("Cannot read storage\n");
        return -1;
    }
    ioPipe fzf = open_pipe(FZF_CMD);
    if (fzf.w == NULL || fzf.r == NULL) {
        STDERR("Cannot pipe to fzf\n");
        return -1;
    }
    secretRecord *secrets = (secretRecord *)storage;
    for (int i = 0; i < STORAGE_LEN; i++) {
        if (secrets[i].last_updated != 0) {
            fprintf(fzf.w, "%s | user: %s\n", secrets[i].id, secrets[i].user);
        }
    }
    fclose(fzf.w);
    char id[33];
    if (fscanf(fzf.r, "%32s", id) != 1) {
        STDERR("Cannot get fzf result\n");
        return -1;
    }

    STDERR("Looking for secret %s\n", id);
    return get_secret(id, NULL, pipe_pw);
    return 0;
}

// save_storage encrypts contents of "storage" variable using the key in "key" variable
// encryption nonce from "nonce" is regenerated, password salt in "salt" is reused.
// To prevent accidental corruption of storage, saves data to temporary file
// and only then renames it to specified name
int save_storage(char *filename) {
    if (key == NULL) {
        STDERR("Storage is not opened");
        return -1;
    }

    size_t tmp_sz = strlen(filename) + 6;
    char *tmp_filename = (char *)malloc(tmp_sz + 1);
    strncpy(tmp_filename, filename, tmp_sz);
    strncat(tmp_filename, "XXXXXX", tmp_sz);

    int filedes = mkstemp(tmp_filename);
    if (filedes < 0) {
        STDERR("Cannot create temporary file: %s\n", strerror(errno));
        return -1;
    }

    // regenerate nonce before re-encoding storage, never reuse nonce
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    // write header
    if (write(filedes, salt, sizeof(salt)) < 0) {
        STDERR("Cannot write to temporary file %s: %s", tmp_filename, strerror(errno));
        return -1;
    }
    if (write(filedes, nonce, sizeof(nonce)) < 0) {
        STDERR("Cannot write to temporary file %s: %s", tmp_filename, strerror(errno));
        return -1;
    }

    // encode storage and write it to the file
    crypto_secretbox_easy(ciphertext, storage, STORAGE_BYTES, nonce, key);
    if (write(filedes, ciphertext, CIPHER_BYTES) < 0) {
        STDERR("Cannot write to temporary file %s: %s", tmp_filename, strerror(errno));
        return -1;
    }

    if (close(filedes) != 0) {
        STDERR("Cannot close temporary file %s: %s\n", tmp_filename, strerror(errno));
        return -1;
    }
    if (rename(tmp_filename, filename) != 0) {
        STDERR("Cannot move temporary file %s to %s: %s\n", tmp_filename, filename, strerror(errno));
        return -1;
    }
    free(tmp_filename);
    STDERR("Storage saved to %s\n", filename);
    return 0;
}

int copy_to_clipboard(char *str) {
    ioPipe clip = open_pipe(CLIPBOARD_CMD);
    if (clip.w == NULL) {
        STDERR("Cannot pipe to %s\n", CLIPBOARD_CMD);
        return -1;
    }

    if (fwrite(str, strlen(str), 1, clip.w) != 1) {
        STDERR("Cannot copy to clipboard\n");
        fclose(clip.w);
        return -1;
    };

    clean_clipboard = 1;
    fclose(clip.w);
    fclose(clip.r);
    return 0;
}

// open_pipe opens bi-directional channel with cmd via two pipes
// ioPipe.r is attached to cmd's stdout
// ioPipe.w is attached to cmd's stdin
ioPipe open_pipe(char *cmd) {
    int rpipe[2];
    int wpipe[2];
    ioPipe r = {.r = NULL, .w = NULL};

    if (pipe(rpipe) != 0) { // reading from cmd
        STDERR("Cannot create pipe: %s", strerror(errno));
        return r;
    }
    if (pipe(wpipe) != 0) { // writing to cmd
        STDERR("Cannot create pipe: %s", strerror(errno));
        return r;
    }

    int child = fork();
    if (child < 0) {
        STDERR("Cannot fork: %s", strerror(errno));
        return r;
    }
    if (child == 0) {
        if (dup2(rpipe[1], STDOUT_FILENO) < 0) { // attach output pipe to stdout
            STDERR("Reading pipe error: %s", strerror(errno));
            exit(-1);
        }
        if (dup2(wpipe[0], STDIN_FILENO) < 0) { // attach input pipe to stdin
            STDERR("Writing pipe error: %s", strerror(errno));
            exit(-1);
        }

        close(rpipe[0]); // close read end of reading pipe
        close(wpipe[1]); // close write end of writing pipe
        if (execlp(cmd, cmd, (char *)NULL) < 0) {
            STDERR("Cannot exec %s: %s\n", cmd, strerror(errno));
            exit(-1);
        }
    }
    close(rpipe[1]);
    close(wpipe[0]);
    r.r = fdopen(rpipe[0], "r");
    r.w = fdopen(wpipe[1], "w");

    return r;
}