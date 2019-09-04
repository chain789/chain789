#include <stdint.h>
#include <sgx_tseal.h>

#include "mbedtls/bignum.h"

#ifndef ENCLAVE_ECDSA_H
#define ENCLAVE_ECDSA_H

#if defined(__cplusplus)
extern "C" {
#endif
int ecdsa_keygen_unseal(const sgx_sealed_data_t *secret, size_t secret_len, unsigned char *pubkey, unsigned char *address);
int ecdsa_keygen_seal(unsigned char *o_sealed, size_t *olen, unsigned char *o_pubkey, unsigned char *o_address);
int ecdsa_sign_m(const uint8_t *data, size_t in_len, uint8_t *rr, uint8_t *ss, uint8_t *vv);
int __ecdsa_seckey_to_pubkey(const mbedtls_mpi *seckey, unsigned char *pubkey, unsigned char *address);
int provision_ecdsa_key(const sgx_sealed_data_t *secret, size_t secret_len);
int get_address(unsigned char *pubkey, unsigned char *address);
#if defined(__cplusplus)
}
#endif
#endif