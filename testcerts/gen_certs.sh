#!/bin/bash

set -o pipefail
set -eux

cfssl gencert -initca <(cat <<EOF
{
  "CN": "openresty-jwt-test-cert",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [{
    "C": "US",
    "ST": "New York",
    "L": "New York",
    "O": "JWT",
    "OU": "WORLDWIDE"
  }],
  "ca": {
    "expiry": "876000h"
  }
}
EOF
) | cfssljson -bare root

cfssl gencert -ca root.pem -ca-key root-key.pem <(cat <<EOF
{
  "CN": "testing.jwt.worldwide",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [{
    "C": "US",
    "ST": "Washington",
    "L": "Seattle",
    "O": "JWT",
    "OU": "Not Worldwide"
  }],
  "hosts": ["testing.jwt.worldwide", "local.testing.jwt.worldwide"]
}
EOF
) | cfssljson -bare cert

openssl x509 -in cert.pem -pubkey -noout > cert-pubkey.pem
