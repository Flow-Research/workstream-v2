#!/usr/bin/env bash
# Generate short-lived credentials for an isolated local test. Never reuse this
# developer CA across deployments. The output directory must not yet exist.
set -euo pipefail
umask 077
mkdir -- "${1:?supply a new identity directory}"
cd -- "$1"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj /CN=WorkStream-local-test-CA -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem -keyout ca.key
for role in node sequencer prover; do
  mkdir "$role"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$role.workstream.internal" -out "$role/request" -keyout "$role/key.pem"
  cat > "$role/extensions" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth,serverAuth
subjectAltName=DNS:$role.workstream.internal
authorityKeyIdentifier=keyid
subjectKeyIdentifier=hash
EOF
  openssl x509 -req -in "$role/request" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 1 -extfile "$role/extensions" -out "$role/cert.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$role/key.pem" -outform DER -out "$role/key.der"
  openssl x509 -in "$role/cert.pem" -outform DER -out "$role/cert.der"
  openssl x509 -in ca.pem -outform DER -out "$role/ca.der"
done
cp node/cert.der sequencer/allowed-client.der
cp sequencer/cert.der prover/allowed-client.der
rm ca.key
