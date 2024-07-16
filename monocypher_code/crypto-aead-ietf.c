#include "monocypher.h"

void crypto_aead_ietf_lock(
        uint8_t *ciphertext,
        uint8_t mac[16],
        const uint8_t key[32],
        const uint8_t nonce[12],
        const uint8_t *additional_data,
        size_t additional_data_size,
        const uint8_t *plaintext,
        size_t text_size
        ) {
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext, mac, additional_data, additional_data_size, plaintext, text_size);
    crypto_wipe(&ctx, sizeof ctx);
}

int crypto_aead_ietf_unlock(
        uint8_t *plaintext,
        const uint8_t mac[16],
        const uint8_t key[32],
        const uint8_t nonce[12],
        const uint8_t *additional_data,
        size_t additional_data_size,
        const uint8_t *ciphertext,    
        size_t text_size
        ) {
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    int result = crypto_aead_read(&ctx, plaintext, mac, additional_data, additional_data_size, ciphertext, text_size);
    crypto_wipe(&ctx, sizeof ctx);
    return result;
}