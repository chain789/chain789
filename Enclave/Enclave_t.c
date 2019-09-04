#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecdsa_sign_m_t {
	int ms_retval;
	const uint8_t* ms_data;
	size_t ms_in_len;
	uint8_t* ms_rr;
	uint8_t* ms_ss;
	uint8_t* ms_vv;
} ms_ecdsa_sign_m_t;

typedef struct ms_provision_ecdsa_key_t {
	int ms_retval;
	const sgx_sealed_data_t* ms_secret;
	size_t ms_secret_len;
} ms_provision_ecdsa_key_t;

typedef struct ms_ecdsa_keygen_seal_t {
	int ms_retval;
	unsigned char* ms_o_sealed;
	size_t* ms_olen;
	unsigned char* ms_o_pubkey;
	unsigned char* ms_o_address;
} ms_ecdsa_keygen_seal_t;

typedef struct ms_ecdsa_keygen_unseal_t {
	int ms_retval;
	const sgx_sealed_data_t* ms_secret;
	size_t ms_secret_len;
	unsigned char* ms_pubkey;
	unsigned char* ms_address;
} ms_ecdsa_keygen_unseal_t;

typedef struct ms_get_address_t {
	int ms_retval;
	unsigned char* ms_pubkey;
	unsigned char* ms_address;
} ms_get_address_t;

typedef struct ms_ocall_mbedtls_net_connect_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const char* ms_host;
	const char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_connect_t;

typedef struct ms_ocall_mbedtls_net_bind_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const char* ms_bind_ip;
	const char* ms_port;
	int ms_proto;
} ms_ocall_mbedtls_net_bind_t;

typedef struct ms_ocall_mbedtls_net_accept_t {
	int ms_retval;
	mbedtls_net_context* ms_bind_ctx;
	mbedtls_net_context* ms_client_ctx;
	void* ms_client_ip;
	size_t ms_buf_size;
	size_t* ms_ip_len;
} ms_ocall_mbedtls_net_accept_t;

typedef struct ms_ocall_mbedtls_net_set_block_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_block_t;

typedef struct ms_ocall_mbedtls_net_set_nonblock_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_set_nonblock_t;

typedef struct ms_ocall_mbedtls_net_usleep_t {
	unsigned long int ms_usec;
} ms_ocall_mbedtls_net_usleep_t;

typedef struct ms_ocall_mbedtls_net_recv_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_recv_t;

typedef struct ms_ocall_mbedtls_net_send_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	const unsigned char* ms_buf;
	size_t ms_len;
} ms_ocall_mbedtls_net_send_t;

typedef struct ms_ocall_mbedtls_net_recv_timeout_t {
	int ms_retval;
	mbedtls_net_context* ms_ctx;
	unsigned char* ms_buf;
	size_t ms_len;
	uint32_t ms_timeout;
} ms_ocall_mbedtls_net_recv_timeout_t;

typedef struct ms_ocall_mbedtls_net_free_t {
	mbedtls_net_context* ms_ctx;
} ms_ocall_mbedtls_net_free_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecdsa_sign_m(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecdsa_sign_m_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecdsa_sign_m_t* ms = SGX_CAST(ms_ecdsa_sign_m_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_data = ms->ms_data;
	size_t _tmp_in_len = ms->ms_in_len;
	size_t _len_data = _tmp_in_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_rr = ms->ms_rr;
	uint8_t* _tmp_ss = ms->ms_ss;
	uint8_t* _tmp_vv = ms->ms_vv;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecdsa_sign_m((const uint8_t*)_in_data, _tmp_in_len, _tmp_rr, _tmp_ss, _tmp_vv);

err:
	if (_in_data) free(_in_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_provision_ecdsa_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_provision_ecdsa_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_provision_ecdsa_key_t* ms = SGX_CAST(ms_provision_ecdsa_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_sealed_data_t* _tmp_secret = ms->ms_secret;
	size_t _tmp_secret_len = ms->ms_secret_len;
	size_t _len_secret = _tmp_secret_len;
	sgx_sealed_data_t* _in_secret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_secret, _len_secret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_secret != NULL && _len_secret != 0) {
		_in_secret = (sgx_sealed_data_t*)malloc(_len_secret);
		if (_in_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_secret, _len_secret, _tmp_secret, _len_secret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = provision_ecdsa_key((const sgx_sealed_data_t*)_in_secret, _tmp_secret_len);

err:
	if (_in_secret) free(_in_secret);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecdsa_keygen_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecdsa_keygen_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecdsa_keygen_seal_t* ms = SGX_CAST(ms_ecdsa_keygen_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_o_sealed = ms->ms_o_sealed;
	size_t* _tmp_olen = ms->ms_olen;
	size_t _len_olen = sizeof(size_t);
	size_t* _in_olen = NULL;
	unsigned char* _tmp_o_pubkey = ms->ms_o_pubkey;
	unsigned char* _tmp_o_address = ms->ms_o_address;

	CHECK_UNIQUE_POINTER(_tmp_olen, _len_olen);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_olen != NULL && _len_olen != 0) {
		if ( _len_olen % sizeof(*_tmp_olen) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_olen = (size_t*)malloc(_len_olen);
		if (_in_olen == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_olen, _len_olen, _tmp_olen, _len_olen)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecdsa_keygen_seal(_tmp_o_sealed, _in_olen, _tmp_o_pubkey, _tmp_o_address);
	if (_in_olen) {
		if (memcpy_s(_tmp_olen, _len_olen, _in_olen, _len_olen)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_olen) free(_in_olen);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecdsa_keygen_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecdsa_keygen_unseal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecdsa_keygen_unseal_t* ms = SGX_CAST(ms_ecdsa_keygen_unseal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_sealed_data_t* _tmp_secret = ms->ms_secret;
	size_t _tmp_secret_len = ms->ms_secret_len;
	size_t _len_secret = _tmp_secret_len;
	sgx_sealed_data_t* _in_secret = NULL;
	unsigned char* _tmp_pubkey = ms->ms_pubkey;
	unsigned char* _tmp_address = ms->ms_address;

	CHECK_UNIQUE_POINTER(_tmp_secret, _len_secret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_secret != NULL && _len_secret != 0) {
		_in_secret = (sgx_sealed_data_t*)malloc(_len_secret);
		if (_in_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_secret, _len_secret, _tmp_secret, _len_secret)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecdsa_keygen_unseal((const sgx_sealed_data_t*)_in_secret, _tmp_secret_len, _tmp_pubkey, _tmp_address);

err:
	if (_in_secret) free(_in_secret);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_address(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_address_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_address_t* ms = SGX_CAST(ms_get_address_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_pubkey = ms->ms_pubkey;
	unsigned char* _tmp_address = ms->ms_address;



	ms->ms_retval = get_address(_tmp_pubkey, _tmp_address);


	return status;
}

static sgx_status_t SGX_CDECL sgx_dummy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	dummy();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecdsa_sign_m, 0},
		{(void*)(uintptr_t)sgx_provision_ecdsa_key, 0},
		{(void*)(uintptr_t)sgx_ecdsa_keygen_seal, 0},
		{(void*)(uintptr_t)sgx_ecdsa_keygen_unseal, 0},
		{(void*)(uintptr_t)sgx_get_address, 0},
		{(void*)(uintptr_t)sgx_dummy, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[16][6];
} g_dyn_entry_table = {
	16,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_mbedtls_net_connect(int* retval, mbedtls_net_context* ctx, const char* host, const char* port, int proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_host = host ? strlen(host) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;

	ms_ocall_mbedtls_net_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_connect_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(host, _len_host);
	CHECK_ENCLAVE_POINTER(port, _len_port);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (host != NULL) ? _len_host : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (port != NULL) ? _len_port : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_connect_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_connect_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	if (host != NULL) {
		ms->ms_host = (const char*)__tmp;
		if (_len_host % sizeof(*host) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, host, _len_host)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_host);
		ocalloc_size -= _len_host;
	} else {
		ms->ms_host = NULL;
	}
	
	if (port != NULL) {
		ms->ms_port = (const char*)__tmp;
		if (_len_port % sizeof(*port) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, port, _len_port)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_port);
		ocalloc_size -= _len_port;
	} else {
		ms->ms_port = NULL;
	}
	
	ms->ms_proto = proto;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_bind(int* retval, mbedtls_net_context* ctx, const char* bind_ip, const char* port, int proto)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_bind_ip = bind_ip ? strlen(bind_ip) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;

	ms_ocall_mbedtls_net_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_bind_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(bind_ip, _len_bind_ip);
	CHECK_ENCLAVE_POINTER(port, _len_port);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bind_ip != NULL) ? _len_bind_ip : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (port != NULL) ? _len_port : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_bind_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_bind_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		memset(__tmp_ctx, 0, _len_ctx);
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	if (bind_ip != NULL) {
		ms->ms_bind_ip = (const char*)__tmp;
		if (_len_bind_ip % sizeof(*bind_ip) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, bind_ip, _len_bind_ip)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bind_ip);
		ocalloc_size -= _len_bind_ip;
	} else {
		ms->ms_bind_ip = NULL;
	}
	
	if (port != NULL) {
		ms->ms_port = (const char*)__tmp;
		if (_len_port % sizeof(*port) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, port, _len_port)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_port);
		ocalloc_size -= _len_port;
	} else {
		ms->ms_port = NULL;
	}
	
	ms->ms_proto = proto;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_accept(int* retval, mbedtls_net_context* bind_ctx, mbedtls_net_context* client_ctx, void* client_ip, size_t buf_size, size_t* ip_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_bind_ctx = sizeof(mbedtls_net_context);
	size_t _len_client_ctx = sizeof(mbedtls_net_context);
	size_t _len_client_ip = buf_size;
	size_t _len_ip_len = sizeof(size_t);

	ms_ocall_mbedtls_net_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_accept_t);
	void *__tmp = NULL;

	void *__tmp_client_ctx = NULL;
	void *__tmp_client_ip = NULL;
	void *__tmp_ip_len = NULL;

	CHECK_ENCLAVE_POINTER(bind_ctx, _len_bind_ctx);
	CHECK_ENCLAVE_POINTER(client_ctx, _len_client_ctx);
	CHECK_ENCLAVE_POINTER(client_ip, _len_client_ip);
	CHECK_ENCLAVE_POINTER(ip_len, _len_ip_len);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bind_ctx != NULL) ? _len_bind_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (client_ctx != NULL) ? _len_client_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (client_ip != NULL) ? _len_client_ip : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ip_len != NULL) ? _len_ip_len : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_accept_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_accept_t);

	if (bind_ctx != NULL) {
		ms->ms_bind_ctx = (mbedtls_net_context*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, bind_ctx, _len_bind_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bind_ctx);
		ocalloc_size -= _len_bind_ctx;
	} else {
		ms->ms_bind_ctx = NULL;
	}
	
	if (client_ctx != NULL) {
		ms->ms_client_ctx = (mbedtls_net_context*)__tmp;
		__tmp_client_ctx = __tmp;
		memset(__tmp_client_ctx, 0, _len_client_ctx);
		__tmp = (void *)((size_t)__tmp + _len_client_ctx);
		ocalloc_size -= _len_client_ctx;
	} else {
		ms->ms_client_ctx = NULL;
	}
	
	if (client_ip != NULL) {
		ms->ms_client_ip = (void*)__tmp;
		__tmp_client_ip = __tmp;
		memset(__tmp_client_ip, 0, _len_client_ip);
		__tmp = (void *)((size_t)__tmp + _len_client_ip);
		ocalloc_size -= _len_client_ip;
	} else {
		ms->ms_client_ip = NULL;
	}
	
	ms->ms_buf_size = buf_size;
	if (ip_len != NULL) {
		ms->ms_ip_len = (size_t*)__tmp;
		__tmp_ip_len = __tmp;
		if (_len_ip_len % sizeof(*ip_len) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_ip_len, 0, _len_ip_len);
		__tmp = (void *)((size_t)__tmp + _len_ip_len);
		ocalloc_size -= _len_ip_len;
	} else {
		ms->ms_ip_len = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (client_ctx) {
			if (memcpy_s((void*)client_ctx, _len_client_ctx, __tmp_client_ctx, _len_client_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (client_ip) {
			if (memcpy_s((void*)client_ip, _len_client_ip, __tmp_client_ip, _len_client_ip)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ip_len) {
			if (memcpy_s((void*)ip_len, _len_ip_len, __tmp_ip_len, _len_ip_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_set_block(int* retval, mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);

	ms_ocall_mbedtls_net_set_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_set_block_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_set_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_set_block_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_set_block_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_set_nonblock(int* retval, mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);

	ms_ocall_mbedtls_net_set_nonblock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_set_nonblock_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_set_nonblock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_set_nonblock_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_set_nonblock_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_usleep(unsigned long int usec)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_mbedtls_net_usleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_usleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_usleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_usleep_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_usleep_t);

	ms->ms_usec = usec;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_recv(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_recv_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_recv_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_recv_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (unsigned char*)__tmp;
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_send(int* retval, mbedtls_net_context* ctx, const unsigned char* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_send_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_send_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_send_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (const unsigned char*)__tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_recv_timeout(int* retval, mbedtls_net_context* ctx, unsigned char* buf, size_t len, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);
	size_t _len_buf = len;

	ms_ocall_mbedtls_net_recv_timeout_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_recv_timeout_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;
	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_recv_timeout_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_recv_timeout_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_recv_timeout_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	if (buf != NULL) {
		ms->ms_buf = (unsigned char*)__tmp;
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_timeout = timeout;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_mbedtls_net_free(mbedtls_net_context* ctx)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ctx = sizeof(mbedtls_net_context);

	ms_ocall_mbedtls_net_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_mbedtls_net_free_t);
	void *__tmp = NULL;

	void *__tmp_ctx = NULL;

	CHECK_ENCLAVE_POINTER(ctx, _len_ctx);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctx != NULL) ? _len_ctx : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_mbedtls_net_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_mbedtls_net_free_t));
	ocalloc_size -= sizeof(ms_ocall_mbedtls_net_free_t);

	if (ctx != NULL) {
		ms->ms_ctx = (mbedtls_net_context*)__tmp;
		__tmp_ctx = __tmp;
		if (memcpy_s(__tmp_ctx, ocalloc_size, ctx, _len_ctx)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctx);
		ocalloc_size -= _len_ctx;
	} else {
		ms->ms_ctx = NULL;
	}
	
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (ctx) {
			if (memcpy_s((void*)ctx, _len_ctx, __tmp_ctx, _len_ctx)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

