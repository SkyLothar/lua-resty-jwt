#!/bin/bash

set -o pipefail
set -eux

cfssl gencert -initca root_ca_params.json | cfssljson -bare root

cfssl gencert -ca root.pem -ca-key root-key.pem cert_params.json | cfssljson -bare cert

openssl x509 -in cert.pem -pubkey -noout > cert-pubkey.pem
