
#ifndef CRYPTO_AEAD_IETF_H
#define CRYPTO_AEAD_IETF_H

#include <stddef.h>
#include <stdint.h>

void crypto_aead_ietf_lock(
        uint8_t *ciphertext,
        uint8_t mac[16],
        const uint8_t key[32],
        const uint8_t nonce[12],
        const uint8_t *additional_data,
        size_t additional_data_size,
        const uint8_t *plaintext,
        size_t text_size
        );

int crypto_aead_ietf_unlock(
        uint8_t *plaintext,
        const uint8_t mac[16],
        const uint8_t key[32],
        const uint8_t nonce[12],
        const uint8_t *additional_data,
        size_t additional_data_size,
        const uint8_t *ciphertext,    
        size_t text_size
        );

#endif // CRYPTO_AEAD_IETF_H

