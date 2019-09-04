#ifndef APP_UTILS_H_
#define APP_UTILS_H_

#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>
#include "sgx_tseal.h"
#include "sgx_urts.h"
using namespace std;

#define SECRETKEY_SEALED_LEN 1024
#define SECKEY_LEN  32
#define PUBKEY_LEN  64
#define ADDRESS_LEN 20

#define TOKEN_FILENAME "inter_chain.enclave.token"
#define ENCLAVE_FILENAME "./Enclave/enclave.debug.so"

int initialize_enclave(const char *name, sgx_enclave_id_t *eid);
void print_error_message(sgx_status_t ret);
const string sgx_error_message(sgx_status_t ret);
string unseal_key(sgx_enclave_id_t eid, string sealed_key, int key_type);
void provision_key(sgx_enclave_id_t eid, string sealed_key, int KeyType);

using bytes = vector<unsigned char>;

bytes hexToBuffer(const string &hex);
void hexToBuffer(const string &hex, vector<uint8_t> *buffer);
void hexToBuffer(const string &str, unsigned char *buffer, size_t bufSize);
string bufferToHex(const unsigned char *, size_t, bool prefix = false);
string bufferToHex(vector<unsigned char> const &buffer, bool prefix = false);

// encoding
int b64_ntop(unsigned char const *src, size_t srclength, char *target, size_t targsize);
// decoding
int b64_pton(const char *src, unsigned char*target, size_t targsize);

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

#endif // APP_UTILS_H_