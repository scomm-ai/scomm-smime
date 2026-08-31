#ifndef SCOMM_SMIME_H
#define SCOMM_SMIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t scomm_smime_abi_version(void);
void scomm_smime_buffer_free(uint8_t *ptr, size_t len);
int32_t scomm_smime_last_error(uint8_t **out, size_t *out_len);

int32_t scomm_smime_inspect(
    const uint8_t *key, size_t key_len,
    uint8_t **json_out, size_t *json_len);

int32_t scomm_smime_generate(
    const uint8_t *userid, size_t userid_len,
    const uint8_t *passphrase, size_t passphrase_len,
    int32_t profile,
    uint8_t **public_out, size_t *public_len,
    uint8_t **secret_out, size_t *secret_len,
    uint8_t **json_out, size_t *json_len);

int32_t scomm_smime_pqc_ready(void);

int32_t scomm_smime_export_public(
    const uint8_t *key, size_t key_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_smime_encrypt(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *recipients, size_t recipients_len,
    int32_t armored,
    uint8_t **out, size_t *out_len);

int32_t scomm_smime_decrypt(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_smime_sign(
    const uint8_t *data, size_t data_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_smime_verify(
    const uint8_t *data, size_t data_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key, size_t public_key_len,
    int32_t *valid_out);

int32_t scomm_smime_inspect_message(
    const uint8_t *message, size_t message_len,
    uint8_t **json_out, size_t *json_len);

int32_t scomm_smime_test_passphrase(
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len);

int32_t scomm_smime_pop_sign_mldsa(
    const uint8_t *data, size_t data_len,
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    uint8_t **out, size_t *out_len);

int32_t scomm_smime_pop_hybrid_shared(
    const uint8_t *private_key, size_t private_key_len,
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *kem_ciphertext, size_t kem_ciphertext_len,
    const uint8_t *ephemeral_x25519, size_t ephemeral_x25519_len,
    uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
