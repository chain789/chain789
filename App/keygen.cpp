#include <sgx_error.h>
#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>
#include <string>

#include "Enclave_u.h"
#include "utils.h"

namespace po = boost::program_options;

void print_key(sgx_enclave_id_t eid, string keyfile) {
  printf("printing key from %s", keyfile.c_str());
  std::ifstream in_keyfile(keyfile);
  if (!in_keyfile.is_open()) {
    std::cerr << "cannot open key file" << endl;
    std::exit(-1);
  }

  std::stringstream buffer;
  buffer << in_keyfile.rdbuf();

  cout << "Sealed Secret: " << buffer.str() << endl;

  unsigned char secret_sealed[SECRETKEY_SEALED_LEN];
  unsigned char pubkey[PUBKEY_LEN];
  unsigned char address[ADDRESS_LEN];

  size_t buffer_used = static_cast<size_t>(
      b64_pton(buffer.str().c_str(), secret_sealed, sizeof secret_sealed));

  int ret = 0;
  sgx_status_t ecall_ret;
  ecall_ret = ecdsa_keygen_unseal(
      eid, &ret, reinterpret_cast<sgx_sealed_data_t *>(secret_sealed),
      buffer_used, pubkey, address);
  if (ecall_ret != SGX_SUCCESS || ret != 0) {
    printf("ecall failed");
    print_error_message(ecall_ret);
    printf("ecdsa_keygen_unseal returns %d", ret);

    std::exit(-1);
  }
  cout << "PublicKey: " << bufferToHex(pubkey, sizeof pubkey, true) << endl;
  cout << "Address: " << bufferToHex(address, sizeof address, true) << endl;
}

void keygen(sgx_enclave_id_t eid, string keyfile) {
  printf("generating key to %s", keyfile.c_str());
  unsigned char secret_sealed[SECRETKEY_SEALED_LEN];
  unsigned char pubkey[PUBKEY_LEN];
  unsigned char address[ADDRESS_LEN];

  // call into enclave to fill the above three buffers
  size_t buffer_used = 0;
  int ret;
  sgx_status_t ecall_status;
  ecall_status = ecdsa_keygen_seal(eid, &ret, secret_sealed, &buffer_used,
                                   pubkey, address);
  if (ecall_status != SGX_SUCCESS || ret != 0) {
    printf("ecall failed");
    print_error_message(ecall_status);
    printf("ecdsa_keygen_seal returns %d", ret);
    std::exit(-1);
  }

  char secret_sealed_b64[SECRETKEY_SEALED_LEN * 2];
  buffer_used = static_cast<size_t>(
      b64_ntop(secret_sealed, sizeof secret_sealed, secret_sealed_b64,
                    sizeof secret_sealed_b64));

  std::ofstream of(keyfile);
  if (!of.is_open()) {
    printf("cannot open key file: %s", keyfile.c_str());
    std::exit(-1);
  }
  of.write(secret_sealed_b64, buffer_used);
  of << endl;
  of.close();

  cout << "PublicKey: " << bufferToHex(pubkey, sizeof pubkey, true) << endl;
  cout << "Address: " << bufferToHex(address, sizeof address, true) << endl;
}

int main(int argc, const char *argv[]) {

  string key_input, key_output;
  string enclave_path;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "print this message")(
        "enclave,e", po::value(&enclave_path)->required(), "which enclave to use?")(
        "print,p", po::value(&key_input), "print existing keys")(
        "keygen,g", po::value(&key_output), "generate a new key");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (vm.count("help")) {
      std::cerr << desc << endl;
      return -1;
    }
    po::notify(vm);
  } catch (po::required_option &e) {
    std::cerr << e.what() << endl;
    return -1;
  } catch (std::exception &e) {
    std::cerr << e.what() << endl;
    return -1;
  } catch (...) {
    std::cerr << "Unknown error!" << endl;
    return -1;
  }

  if ((key_input.empty() && key_output.empty()) ||
      (!key_input.empty() && !key_output.empty())) {
    std::cerr << "print specify exactly one command" << endl;
    std::exit(-1);
  }

  sgx_enclave_id_t eid;
  sgx_status_t st;
  int ret;

  ret = initialize_enclave(enclave_path.c_str(), &eid);
  if (ret != 0) {
    printf("Failed to initialize the enclave");
    std::exit(-1);
  } else {
    printf("enclave %lu created", eid);
  }

  if (!key_input.empty()) {
    print_key(eid, key_input);
  } else if (!key_output.empty()) {
    keygen(eid, key_output);
  }

  sgx_destroy_enclave(eid);
  printf("Info: all enclave closed successfully.");
}