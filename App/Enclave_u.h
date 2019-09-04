#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_tseal.h"
#include "mbedtls/net_v.h"
#include "mbedtls/timing_v.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_MBEDTLS_NET_CONNECT_DEFINED__
#define OCALL_MBEDTLS_NET_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_connect, (mbedtls_net_context* ctx, const char* host, const char* port, int proto));
#endif
#ifndef OCALL_MBEDTLS_NET_BIND_DEFINED__
#define OCALL_MBEDTLS_NET_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_bind, (mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto));
#endif
#ifndef OCALL_MBEDTLS_NET_ACCEPT_DEFINED__
#define OCALL_MBEDTLS_NET_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_accept, (mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len));
#endif
#ifndef OCALL_MBEDTLS_NET_SET_BLOCK_DEFINED__
#define OCALL_MBEDTLS_NET_SET_BLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_set_block, (mbedtls_net_context* ctx));
#endif
#ifndef OCALL_MBEDTLS_NET_SET_NONBLOCK_DEFINED__
#define OCALL_MBEDTLS_NET_SET_NONBLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_set_nonblock, (mbedtls_net_context* ctx));
#endif
#ifndef OCALL_MBEDTLS_NET_USLEEP_DEFINED__
#define OCALL_MBEDTLS_NET_USLEEP_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_usleep, (unsigned long int usec));
#endif
#ifndef OCALL_MBEDTLS_NET_RECV_DEFINED__
#define OCALL_MBEDTLS_NET_RECV_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_recv, (mbedtls_net_context* ctx, unsigned char* buf, size_t len));
#endif
#ifndef OCALL_MBEDTLS_NET_SEND_DEFINED__
#define OCALL_MBEDTLS_NET_SEND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_send, (mbedtls_net_context* ctx, const unsigned char* buf, size_t len));
#endif
#ifndef OCALL_MBEDTLS_NET_RECV_TIMEOUT_DEFINED__
#define OCALL_MBEDTLS_NET_RECV_TIMEOUT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_recv_timeout, (mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout));
#endif
#ifndef OCALL_MBEDTLS_NET_FREE_DEFINED__
#define OCALL_MBEDTLS_NET_FREE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mbedtls_net_free, (mbedtls_net_context* ctx));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecdsa_sign_m(sgx_enclave_id_t eid, int* retval, const uint8_t* data, size_t in_len, uint8_t* rr, uint8_t* ss, uint8_t* vv);
sgx_status_t provision_ecdsa_key(sgx_enclave_id_t eid, int* retval, const sgx_sealed_data_t* secret, size_t secret_len);
sgx_status_t ecdsa_keygen_seal(sgx_enclave_id_t eid, int* retval, unsigned char* o_sealed, size_t* olen, unsigned char* o_pubkey, unsigned char* o_address);
sgx_status_t ecdsa_keygen_unseal(sgx_enclave_id_t eid, int* retval, const sgx_sealed_data_t* secret, size_t secret_len, unsigned char* pubkey, unsigned char* address);
sgx_status_t get_address(sgx_enclave_id_t eid, int* retval, unsigned char* pubkey, unsigned char* address);
sgx_status_t dummy(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
