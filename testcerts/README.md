# Test certificates

These certificates have been generated using the `cfssl` tool and the
`gen_certs.sh` script included in this directory.

Please note that generating new certificates will break some tests due to
encoded jwt strings, based on the certificates present in this directory, being
hardcoded in some tests.


The keypair was retrieved from http://fm4dd.com/openssl/certexamples.htm

- 2048 RSA keypair: http://fm4dd.com/openssl/source/PEM/keys/2048b-rsa-example-keypair.pem
