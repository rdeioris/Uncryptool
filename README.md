# Uncryptool

This is an Unreal Engine plugin for exposing (to both C++ and Blueprints) cryptographic functions.

Currently it can be used for:

* AES and ChaCha20 Encrypt/Decrypt
* RSA Encrypt/Decrypt and Sign/Verify
* Hashing (SHA256, SHA384, SHA512, RIPEMD160, SHA1, SHA224, BLAKE2b512, BLAKE2s256)
* "Cryptographically-secure" random numbers generation
* BigNumbers math
* Elliptic Curve Sign/Verify and Encrypt/Decrypt
* Data Encoding/Decoding (Base64, Base58Check, Hex, Bech32)
* Support for the "age" format (https://github.com/FiloSottile/age) as well as the openssl "salted" format.
* Key Derivation functions (PBKDF2, Scrypt, HKDF, OpenSSL Legacy)
* Binary Structures Packer/Unpacker (same api of python struct module https://docs.python.org/3/library/struct.html)

It wraps the OpenSSL library included in standard Unreal Engine distributions.

## Usage

## Technical Notes
