I can neither confirm nor deny this is a password manager, a very minimalistic one.

There certainly is a plethora of various managers with better functionality, and let's be honest - likely you _should_ use them instead of this one. 

At least unless you, like myself, are having trust issues with things that are too complex or simply not that open to fully understand. Especially around such a delicate matter as storing passwords. That being said, the main intention of the project is to create a password manager under 1K lines of (pretty simple) code, so anyone caring enough can take a look into its sources and confirm it's not doing anything fishy/stupid/too complicated. Due to this requirement, the functionality is, and probably forever will be, is minimal: it only can store and get passwords from encrypted file. It doesn't do cloud synchronization, neither it has mobile app.

Apart from that, the only other notable feature is that secret storage file of fixed size (around 610K) that can only store 1000 secrets (you can tune this value by changing STORAGE_LEN macro). The only reason for that is weird flex of hiding how much passwords you are storing and whether you do this at all (so you, essentially, can neither confirm nor deny you have passwords there). 

# Installation
The only dependency is [libsodium](https://doc.libsodium.org/). Linux folks will also require libbsd. 
```bash
make
make install    # specify DESTDIR to customize
``` 
Default install location is `/usr/bin` in Linux and `/usr/local/bin` in BSDs.

# Usage

1. Init the storage: `ncod -i [-f FILE]`
2. Store the secret: `ncod -s SECRET_ID [-f FILE]`
3. Get the secret: `ncod -g SECRET_ID [-f FILE]` 
