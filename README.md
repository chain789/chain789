## 编译
```
cmake .
make
```

## 使用
运行demo
```
App/a.out
```

在程序中使用
```
App/a.out nonce value address data gas gasprice
```
输出交易经过签名的rlp编码

查看签名的密钥信息
```
App/keygen --enclave Enclave/enclave.debug.so --print App/keyfile
```

生成新的密钥
App/keygen --enclave Enclave/enclave.debug.so --keygen App/keyfile