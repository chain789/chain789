#include "utils.h"
#include <iostream>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <string>
#include "Enclave_u.h"
#include <assert.h>

using namespace std;

/*!
 * \brief   Initialize the enclave:
 *      Step 1: try to retrieve the launch token saved by last transaction
 *      Step 2: call sgx_create_enclave to initialize an enclave instance
 *      Step 3: save the launch token if it is updated
 * \param enclave_name full path to the enclave binary
 * \param eid [out] place to hold enclave id
 */

namespace fs = boost::filesystem;
#define Assert(Cond)                                                           \
  if (!(Cond))                                                                 \
  abort()

int initialize_enclave(const char *enclave_name, sgx_enclave_id_t *eid) {
  if (!fs::exists(enclave_name)) {
    printf("Enclave file %s doesn't not exist", enclave_name);
    return -1;
  }
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = false;

  /*! Step 1: try to retrieve the launch token saved by last transaction
   *         if there is no token, then create a new one.
   */
  const char *token_path = TOKEN_FILENAME;
  FILE *fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    printf("Warning: Failed to create/open the launch token file \"%s\".\n",
           token_path);
  }

  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }
  /*! Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(enclave_name, SGX_DEBUG_FLAG, &token, &updated, eid,
                           NULL);
  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    if (fp != NULL)
      fclose(fp);
    return -1;
  }

  /* Step 3: save the launch token if it is updated */
  if (updated == -1 || fp == NULL) {
    /* if the token is not updated, or file handle is invalid, do not perform
     * saving */
    if (fp != NULL)
      fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL)
    return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return 0;
}

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, "
     "and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
    {SGX_ERROR_SERVICE_UNAVAILABLE,
     "AE service did not respond or the requested service is not supported.",
     NULL}};

void print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error: returned %x\n", ret);
}

void provision_key(sgx_enclave_id_t eid, string sealed_key, int type) {
  unsigned char _sealed_key_buf[SECRETKEY_SEALED_LEN];
  auto buffer_used = (size_t)b64_pton(sealed_key.c_str(), _sealed_key_buf, sizeof _sealed_key_buf);

  int ret = 0;
  sgx_status_t ecall_ret;
  ecall_ret = provision_ecdsa_key(eid, &ret,
                                          reinterpret_cast<sgx_sealed_data_t*>(_sealed_key_buf), buffer_used);

  if (ecall_ret != SGX_SUCCESS || ret != 0) {
    cout << string(ecall_ret +  "provision_key returns " + to_string(ret)) << endl;
    exit(-1);
  }
}

/*!
 * unseal the secret signing and return the corresponding address
 * @param[in] eid
 * @param[in] sealed_key
 * @return a string of corresponding address
 */
string unseal_key(sgx_enclave_id_t eid, string sealed_key, int key_type) {
  unsigned char secret_sealed[SECRETKEY_SEALED_LEN];
  unsigned char pubkey[PUBKEY_LEN];
  unsigned char address[ADDRESS_LEN];

  size_t buffer_used = (size_t)b64_pton(sealed_key.c_str(), secret_sealed,
                                             sizeof secret_sealed);

  int ret = 0;
  sgx_status_t ecall_ret;
  ecall_ret = ecdsa_keygen_unseal(
      eid, &ret, reinterpret_cast<sgx_sealed_data_t*>(secret_sealed),
      buffer_used, pubkey, address);
  if (ecall_ret != SGX_SUCCESS || ret != 0) {
    cout << string(ecall_ret + "ecdsa_keygen_unseal failed with " + to_string(ret)) << endl;
  }
  return bufferToHex(address, sizeof address, true);
}


void hexToBuffer(const string &str, unsigned char *buffer, size_t bufSize) {
  if (buffer == nullptr) throw invalid_argument("buffer is null");
  if (str.size() == 0) return;

  auto offset = (str.compare(0, 2, "0x") == 0) ? 2 : 0;
  if ((str.size() - offset) / 2 > bufSize) {
    throw invalid_argument("buffer is too small");
  }
  boost::algorithm::unhex(str.begin() + offset, str.end(), buffer);
}

bytes hexToBuffer(const string& hex) {
  bytes r;
  auto offset = (hex.compare(0, 2, "0x") == 0) ? 2 : 0;
  boost::algorithm::unhex(hex.begin() + offset, hex.end(), back_inserter(r));

  return r;
}

void hexToBuffer(const string &hex, vector<uint8_t> *buffer) {
  if (buffer == nullptr) {
    throw invalid_argument("null output ptr");
  }
  if (hex.size() == 0) {
    buffer->clear();
    return;
  }

  auto offset = (hex.compare(0, 2, "0x") == 0) ? 2 : 0;
  boost::algorithm::unhex(hex.begin() + offset, hex.end(),
                          back_inserter(*buffer));
}

string bufferToHex(const unsigned char *buffer, size_t bufSize, bool prefix) {
  string hex;
  if (prefix) {
    hex += "0x";
  }
  boost::algorithm::hex(buffer, buffer + bufSize, back_inserter(hex));
  return hex;
}

string bufferToHex(const vector<unsigned char> &buffer, bool prefix) {
  string hex;
  if (prefix) {
    hex += "0x";
  }
  boost::algorithm::hex(buffer.begin(), buffer.end(), back_inserter(hex));
  return hex;
}


static const char Base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';
int b64_ntop(unsigned char const *src, size_t srclength, char *target,
                  size_t targsize) {
  size_t datalength = 0;
  unsigned char input[3];
  unsigned char output[4];
  size_t i;

  while (2 < srclength) {
    input[0] = *src++;
    input[1] = *src++;
    input[2] = *src++;
    srclength -= 3;

    output[0] = input[0] >> 2;
    output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
    output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
    output[3] = input[2] & 0x3f;
    Assert(output[0] < 64);
    Assert(output[1] < 64);
    Assert(output[2] < 64);
    Assert(output[3] < 64);

    if (datalength + 4 > targsize)
      return (-1);
    target[datalength++] = Base64[output[0]];
    target[datalength++] = Base64[output[1]];
    target[datalength++] = Base64[output[2]];
    target[datalength++] = Base64[output[3]];
  }

  /* Now we worry about padding. */
  if (0 != srclength) {
    /* Get what's left. */
    input[0] = input[1] = input[2] = '\0';
    for (i = 0; i < srclength; i++)
      input[i] = *src++;

    output[0] = input[0] >> 2;
    output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
    output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
    Assert(output[0] < 64);
    Assert(output[1] < 64);
    Assert(output[2] < 64);

    if (datalength + 4 > targsize)
      return (-1);
    target[datalength++] = Base64[output[0]];
    target[datalength++] = Base64[output[1]];
    if (srclength == 1)
      target[datalength++] = Pad64;
    else
      target[datalength++] = Base64[output[2]];
    target[datalength++] = Pad64;
  }
  if (datalength >= targsize)
    return (-1);
  target[datalength] = '\0'; /* Returned value doesn't count \0. */
  return (datalength);
}

/* skips all whitespace anywhere.
   converts characters, four at a time, starting at (or after)
   src from base - 64 numbers into three 8 bit bytes in the target area.
   it returns the number of data bytes stored at the target, or -1 on error.
 */

int b64_pton(const char *src, unsigned char *target, size_t targsize) {
  int tarindex, state, ch;
  unsigned char nextbyte;
  const char *pos;

  state = 0;
  tarindex = 0;

  while ((ch = *src++) != '\0') {
    if (isspace((unsigned char)ch)) /* Skip whitespace anywhere. */
      continue;

    if (ch == Pad64)
      break;

    pos = strchr(Base64, ch);
    if (pos == NULL) /* A non-base64 character. */
      return (-1);

    switch (state) {
    case 0:
      if (target) {
        if ((size_t)tarindex >= targsize)
          return (-1);
        target[tarindex] = (pos - Base64) << 2;
      }
      state = 1;
      break;
    case 1:
      if (target) {
        if ((size_t)tarindex >= targsize)
          return (-1);
        target[tarindex] |= (pos - Base64) >> 4;
        nextbyte = ((pos - Base64) & 0x0f) << 4;
        if ((size_t)tarindex + 1 < targsize)
          target[tarindex + 1] = nextbyte;
        else if (nextbyte)
          return (-1);
      }
      tarindex++;
      state = 2;
      break;
    case 2:
      if (target) {
        if ((size_t)tarindex >= targsize)
          return (-1);
        target[tarindex] |= (pos - Base64) >> 2;
        nextbyte = ((pos - Base64) & 0x03) << 6;
        if ((size_t)tarindex + 1 < targsize)
          target[tarindex + 1] = nextbyte;
        else if (nextbyte)
          return (-1);
      }
      tarindex++;
      state = 3;
      break;
    case 3:
      if (target) {
        if ((size_t)tarindex >= targsize)
          return (-1);
        target[tarindex] |= (pos - Base64);
      }
      tarindex++;
      state = 0;
      break;
    default:
      abort();
    }
  }

  /*
   * We are done decoding Base-64 chars.  Let's see if we ended
   * on a byte boundary, and/or with erroneous trailing characters.
   */

  if (ch == Pad64) { /* We got a pad char. */
    ch = *src++;     /* Skip it, get next. */
    switch (state) {
    case 0: /* Invalid = in first position */
    case 1: /* Invalid = in second position */
      return (-1);

    case 2: /* Valid, means one byte of info */
      /* Skip any number of spaces. */
      for ((void)NULL; ch != '\0'; ch = *src++)
        if (!isspace((unsigned char)ch))
          break;
      /* Make sure there is another trailing = sign. */
      if (ch != Pad64)
        return (-1);
      ch = *src++; /* Skip the = */
    /* Fall through to "single trailing =" case. */
    /* FALLTHROUGH */

    case 3: /* Valid, means two bytes of info */
            /*
             * We know this char is an =.  Is there anything but
             * whitespace after it?
             */
      for ((void)NULL; ch != '\0'; ch = *src++)
        if (!isspace((unsigned char)ch))
          return (-1);

      /*
       * Now make sure for cases 2 and 3 that the "extra"
       * bits that slopped past the last full byte were
       * zeros.  If we don't check them, they become a
       * subliminal channel.
       */
      if (target && (size_t)tarindex < targsize && target[tarindex] != 0)
        return (-1);
      break;
    default:
      abort();
    }
  } else {
    /*
     * We ended by seeing the end of the string.  Make sure we
     * have no partial bytes lying around.
     */
    if (state != 0)
      return (-1);
  }

  return (tarindex);
}

int ocall_print_string(const char* str)
{
    /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
    int ret = printf("%s", str);
    fflush(stdout);
    return ret;
}