# lkcf-engine

An OpenSSL engine based on LKCF(Linux kernel Crypto Framework).

## Dependency

lkcf-engine depends on keyutils pkg [keyutils-1.6.1](https://packages.debian.org/bullseye/amd64/keyutils/download),
and your linux kernel should have enabled pkcs8_key_parser.

## Build
```shell
make
```
## Run test

```shell
# enable pkcs8_key_parser if needed, generally it is compiled as a kernel module
# and needs to be enabled with the following command.
modprobe pkcs8_key_parser

# build example
make example

# run openssl test
make test

# run example
OPENSSL_ENGINES=`pwd` ./example/example

# install
cp ./lkcf-engine.so `openssl version -e | grep -o -P '(?<=").*(?=")'`
```

## Limits
- Currently only RSA is supported, DH is in the plan.
- You'better load engine at main thread, otherwise, do not share
methode object(eg: RSA object) between threads.
- Make sure you system supports keyutils API, and pkcs8_key_parser
is installed, otherwise engine fallthough to OpenSSL-default.
- Asynchronous mode is not support yet
- OpenSSL 1.1.1n introduced misleading error message(undefined symbol: EVP_PKEY_get_base_id)
during engine load which can be ignored as it is not a real failure. This is later fixed in
OpenSSL* 1.1.1o release.
