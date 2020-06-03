#include <stdlib.h>
#include <stdio.h>
#include "monocypher.h"
#include "sha512.h"

// SKIP:
// crypto_lock_encrypt
// crypto_lock_auth

typedef uint8_t u8;

#define ARRAY(name, size) \
    u8 name[size]; \
    for(size_t i = 0; i < size; i++) name[i] = i;


void verify(void) {
    ARRAY(a, 65);
    ARRAY(b, 65);
    crypto_verify16(a, b);
    crypto_verify32(a, b);
    crypto_verify64(a, b);
}

void wipe(void) {
    ARRAY(a, 123);
    crypto_wipe(a,   0);
    crypto_wipe(a, 123);
}

void lock_unlock(void) {
    ARRAY(mac,   16);
    ARRAY(enc,   64);
    ARRAY(txt,   64);
    ARRAY(key,   33);
    ARRAY(nonce, 25);
    crypto_lock  (mac, enc, key, nonce, txt, 0);
    crypto_unlock(txt, key, nonce, mac, enc, 0);

    crypto_lock  (mac, enc, key, nonce, txt, 64);
    crypto_unlock(txt, key, nonce, mac, enc, 64);
}

void blake2b(void) {
    ARRAY(hash, 64);
    ARRAY(key,  64);
    ARRAY(in,  129);
    crypto_blake2b_general(hash, 64, key, 64, in,   0);
    crypto_blake2b_general(hash, 64, key, 64, in, 129);
}

void argon(void) {
    ARRAY(hash, 16);
    ARRAY(wrk,  8192); // 8 * 1024
    ARRAY(pwd,  16);
    ARRAY(key,  16);
    ARRAY(slt,  16);
    ARRAY(ad,   16);
    crypto_argon2i_general(hash, 16, wrk, 8, 3, pwd, 16, slt, 16, key, 16, ad, 16);
}

void key_exchange(void) {
    ARRAY(shd, 32);
    ARRAY(key, 32);
    // crypto_key_exchange_public_key is crypto_x25519_public_key
    crypto_key_exchange(shd, key, key);
}

void sign_check(void) {
    ARRAY(hash, 64);
    ARRAY(key,  32);
    ARRAY(pub,  32);
    ARRAY(in,   32);
    crypto_sign_public_key(pub, key);
    crypto_sign(hash, key, pub, in, 32);
    crypto_check(hash, pub, in, 32);
}

void hchacha(void) {
    ARRAY(out, 32);
    ARRAY(key, 32);
    ARRAY(in,  16);
    crypto_chacha20_H(out, key, in);
}

void chacha20_init(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
    crypto_chacha_ctx ctx;

    crypto_chacha20_init(&ctx, key, nonce);
    crypto_chacha20_encrypt(&ctx, out, in, 32);
}

void chacha20_x_init(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    crypto_chacha_ctx ctx;

    crypto_chacha20_x_init(&ctx, key, nonce);
    crypto_chacha20_encrypt(&ctx, out, in, 32);
}

void p1305(void) {
    ARRAY(mac, 16);
    ARRAY(key, 32);
    ARRAY(in,  64);
    crypto_poly1305(mac, in,  0, key);
    crypto_poly1305(mac, in, 64, key);
}

void x25519(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(shr, 32);
    key[0] = 0;
    crypto_x25519_public_key(pub, key);
    crypto_x25519(shr, key, pub);
}

void sha512(void) {
    ARRAY(hash,  64);
    ARRAY(in  , 128);
    crypto_sha512(hash, in,   0);
    crypto_sha512(hash, in, 128);
}

int main(void) {
    verify();
    wipe();
    lock_unlock();
    blake2b();
    argon();
    key_exchange();
    sign_check();
    hchacha();
    chacha20_init();
    chacha20_x_init();
    p1305();
    x25519();
    sha512();
    return 0;
}
