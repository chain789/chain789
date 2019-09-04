#include <stdio.h>
#include "sgx_tseal.h"
#include "eth_ecdsa.h"
#include <string.h>
#include "stddef.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "sgx.h"
#include "external/keccak.h"

#include "glue.h"

#define ECPARAMS MBEDTLS_ECP_DP_SECP256K1
#define _FALSE false
#ifndef LOG_BUILD_LEVEL
#ifdef NDEBUG
#define LOG_BUILD_LEVEL LOG_LVL_CRITICAL
#else
#define LOG_BUILD_LEVEL LOG_LVL_DEBUG
#endif
#endif
// define in mbedtls-SGX/trusted/glue.c
extern int printf_sgx(const char *fmt, ...);
enum {
  LOG_LVL_NONE, // 0
  LOG_LVL_CRITICAL, // 1
  LOG_LVL_WARNING, // 2
  LOG_LVL_NOTICE, // 3
  LOG_LVL_LOG, // 4
  LOG_LVL_DEBUG, // 5
  LOG_LVL_NEVER // 6
};
unsigned char log_run_level = LOG_LVL_DEBUG;
const char *log_level_strings[] = {
    "NONE", // 0
    "CRIT", // 1
    "WARN", // 2
    "NOTI", // 3
    " LOG", // 4
    "DEBG" // 5
};

static mbedtls_mpi g_secret_key;


#define LOG_SHOULD_I(level) ( level <= LOG_BUILD_LEVEL && level <= log_run_level )
#define LOG(level, fmt, arg...) do {    \
    if ( LOG_SHOULD_I(level) ) { \
        printf_sgx("[%s] (%s:%d) " fmt "\n", log_level_strings[level], strrchr(__FILE__, '/')+1,__LINE__, ##arg); \
    } \
} while(_FALSE)

#define LL_CRITICAL(fmt, arg...) LOG(LOG_LVL_CRITICAL, fmt, ##arg )
#define LL_LOG(fmt, arg...) LOG(LOG_LVL_LOG, fmt,##arg )



/*
typedef uint32_t mbedtls_mpi_uint;

typedef struct mbedtls_mpi {
    int s;
    size_t n;
    mbedtls_mpi_uint* p;
}
*/

int __ecdsa_seckey_to_pubkey(const mbedtls_mpi* seckey, unsigned char* pubkey,
    unsigned char* address)
{
    if (pubkey == NULL || address == NULL || seckey == NULL) {
        return -1;
    }

    mbedtls_ecdsa_context ctx;
    unsigned char __pubkey[65];
    unsigned char __address[32];
    size_t buflen = 0;
    int ret;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_ecp_group_load(&ctx.grp, ECPARAMS);

    mbedtls_mpi_copy(&ctx.d, seckey);

    ret = mbedtls_ecp_mul(&ctx.grp, &ctx.Q, &ctx.d, &ctx.grp.G, NULL, NULL);
    if (ret != 0) {
        LL_CRITICAL("Error: mbedtls_ecp_mul returned %d", ret);
        return -1;
    }

    ret = mbedtls_ecp_point_write_binary(
        &ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen, __pubkey, 65);
    if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
        LL_CRITICAL("buffer too small");
        return -1;
    }
    else if (ret == MBEDTLS_ERR_ECP_BAD_INPUT_DATA) {
        LL_CRITICAL("bad input data");
        return -1;
    }
    if (buflen != 65) {
        LL_CRITICAL("ecp serialization is incorrect olen=%ld", buflen);
    }

    ret = keccak(__pubkey + 1, 64, __address, 32);
    if (ret != 0) {
        LL_CRITICAL("keccak returned %d", ret);
        return -1;
    }

    // copy to user space
    memcpy(pubkey, __pubkey + 1, 64);
    memcpy(address, __address + 12, 20);
    return 0;
}

int ecdsa_sign_m(const uint8_t* data, size_t in_len, uint8_t* rr, uint8_t* ss,
    uint8_t* vv)
{
    int ret;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ecp_group_load(&ctx_sign.grp, ECPARAMS);

    if (g_secret_key.p == NULL) {
        LL_CRITICAL(
            "signing key not provisioned yet. Call tc_provision_key() first");
        return -1;
    }
    ret = mbedtls_mpi_copy(&ctx_sign.d, &g_secret_key);
    if (ret != 0) {
        LL_CRITICAL("Error: mbedtls_mpi_copy returned %d", ret);
        return -1;
    }
    ret = mbedtls_ecp_mul(&ctx_sign.grp, &ctx_sign.Q, &ctx_sign.d,
        &ctx_sign.grp.G, NULL, NULL);
    if (ret != 0) {
        LL_CRITICAL("Error: mbedtls_ecp_mul returned %d", ret);
        return -1;
    }

    ret = mbedtls_ecdsa_sign_with_v(&ctx_sign.grp, &r, &s, vv, &ctx_sign.d, data, in_len, mbedtls_sgx_drbg_random, NULL);

    if (ret != 0) {
        LL_CRITICAL("mbedtls_ecdsa_sign_bitcoin returned %#x", ret);
        goto exit;
    }

    mbedtls_mpi_write_binary(&r, rr, 32);
    mbedtls_mpi_write_binary(&s, ss, 32);

    ret = mbedtls_ecdsa_verify(&ctx_sign.grp, data, in_len, &ctx_sign.Q, &r, &s);
    if (ret != 0) {
        LL_CRITICAL("Error: mbedtls_ecdsa_verify returned %#x", ret);
        goto exit;
    }
    else {
    }

exit:
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        LL_CRITICAL("Last error was: -0x%X - %s", -ret, error_buf);
    }
    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return (ret);
}

// sgx导入私钥
int provision_ecdsa_key(const sgx_sealed_data_t* secret, size_t secret_len)
{
    // used by edge8r
    (void)secret_len;

    uint32_t decrypted_text_length = sgx_get_encrypt_txt_len(secret);
    uint8_t y[decrypted_text_length];
    sgx_status_t st;

    st = sgx_unseal_data(secret, NULL, 0, y, &decrypted_text_length);
    if (st != SGX_SUCCESS) {
        LL_CRITICAL("unseal returned %#x", st);
        return -1;
    }

    // initialize the global secret key
    mbedtls_mpi_init(&g_secret_key);
    return mbedtls_mpi_read_binary(&g_secret_key, y, sizeof y);
}

// 从封印的私钥中恢复公钥和地址
int ecdsa_keygen_unseal(const sgx_sealed_data_t* secret, size_t secret_len,
    unsigned char* pubkey, unsigned char* address)
{
    // used by edge8r
    (void)secret_len;

    uint32_t decrypted_text_length = sgx_get_encrypt_txt_len(secret);
    uint8_t y[decrypted_text_length];
    sgx_status_t st;

    st = sgx_unseal_data(secret, NULL, 0, y, &decrypted_text_length);
    if (st != SGX_SUCCESS) {
        LL_CRITICAL("unseal returned %x", st);
        return -1;
    }

    // initialize the local secret key
    mbedtls_mpi secret_key;
    mbedtls_mpi_init(&secret_key);
    mbedtls_mpi_read_binary(&secret_key, y, sizeof y);

    return __ecdsa_seckey_to_pubkey(&secret_key, pubkey, address);
}

// 生成新的密钥对，返回公钥，地址，封印后的私钥
int ecdsa_keygen_seal(unsigned char* o_sealed, size_t* olen,
    unsigned char* o_pubkey, unsigned char* o_address)
{
    mbedtls_ecp_group grp;
    int ret = 0;

    mbedtls_mpi secret;
    mbedtls_mpi_init(&secret);

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);
#ifdef PREDEFINED_SECKEY
    LL_CRITICAL("*** PREDEFINED SECRET KEY IS USED ***");
    LL_CRITICAL("*** DISABLE THIS BEFORE DEPLOY ***");
    ret = mbedtls_mpi_read_string(&secret, 16, PREDEFINED_SECKEY);
    if (ret != 0) {
        LL_CRITICAL("Error: mbedtls_mpi_read_string returned %d", ret);
        return -1;
    }
#else
    mbedtls_mpi_fill_random(&secret, grp.nbits / 8, mbedtls_sgx_drbg_random,
        NULL);
#endif

    unsigned char secret_buffer[32];
    if (mbedtls_mpi_write_binary(&secret, secret_buffer, sizeof secret_buffer) != 0) {
        LL_CRITICAL("can't run secret to buffer");
        ret = -1;
        goto exit;
    }

    // seal the data
    {
        uint32_t len = sgx_calc_sealed_data_size(0, sizeof(secret_buffer));
        sgx_sealed_data_t* seal_buffer = (sgx_sealed_data_t*)malloc(len);
        LL_LOG("sealed secret length is %d", len);

        sgx_status_t st = sgx_seal_data(0, NULL, sizeof secret_buffer,
            secret_buffer, len, seal_buffer);
        if (st != SGX_SUCCESS) {
            LL_LOG("Failed to seal. Ecall returned %d", st);
            ret = -1;
            goto exit;
        }

        *olen = len;
        memcpy(o_sealed, seal_buffer, len);
        free(seal_buffer);
    }

    if (__ecdsa_seckey_to_pubkey(&secret, o_pubkey, o_address) != 0) {
        LL_CRITICAL("failed to get public key");
        ret = -1;
        goto exit;
    }
    LL_LOG("generate key success");

exit:
    mbedtls_mpi_free(&secret);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

// 获得当前私钥的公钥和地址
int get_address(unsigned char* pubkey, unsigned char* address)
{
    if (g_secret_key.p == NULL) {
        LL_CRITICAL(
            "key has not been provisioned yet. Call tc_provision_key() first");
        return -1;
    }
    return __ecdsa_seckey_to_pubkey(&g_secret_key, pubkey, address);
}


