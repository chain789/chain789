#include <iostream>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <libethereum/Transaction.h>
#include <libdevcore/RLP.h>
#include <libdevcore/Address.h>
#include <libdevcore/CommonData.h>
#include <libdevcore/Common.h>

#include "sgx_urts.h"
#include "utils.h"
#include "Enclave_u.h"

using namespace std;
using namespace dev;
using namespace dev::eth;

// global vars
sgx_enclave_id_t eid;
sgx_status_t st;
void init(){
    // init enclave environment
    int ret = 0;
    ret = initialize_enclave(ENCLAVE_FILENAME, &eid);
    if (ret != 0) {
        printf("sgx_create_enclave error!\n");
        return ;
    }
    string sign_key_file = "App/keyfile";
    ifstream t(sign_key_file);
    stringstream buffer;
    buffer << t.rdbuf();
    string sealed_key(buffer.str());
    try {
        provision_key(eid, sealed_key, 0);
    }catch (const std::exception &e) {
        printf("%s", e.what());
        exit(-1);
    }
}

void demo(){
    u256 value = u256(1) << 2;
    u256 gasPrice = 200;
    u256 gas = 400000;
    Address dest("008d8aaab28575177049acf57aaaed0b8b228b51");
    bytes data = vector<byte>();
    u256 nonce(7);
    Transaction ts(value, gasPrice, gas, dest, data, nonce);
    ts.enclave_sign();
    RLPStream rlp;
    ts.streamRLP(rlp);
    cout << "rlp: " << toHex(rlp.out()) << endl;
    cout << "Transaction sender: " << ts.safeSender() << endl;
}

int main(int argc, char **argv){
    init();
    if(argc == 1) {
        demo();
    }else{
        u256 nonce(argv[1]);
        u256 value(argv[2]);
        Address dest(argv[3]);
        bytes data = fromHex(string(argv[4])) ;
        u256 gas(argv[5]);
        u256 gasPrice(argv[6]);
        Transaction ts(value, gasPrice, gas, dest, data, nonce);
        ts.enclave_sign();
        RLPStream rlp;
        ts.streamRLP(rlp);
        sgx_destroy_enclave(eid);
        cout << toHex(rlp.out()) << endl; // cout will be catched by python or js
    }
    return 0;
}