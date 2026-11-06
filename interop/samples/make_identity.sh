#!/usr/bin/env bash
# Makes a throwaway S/MIME identity for capturing client samples. See README.md.
# The private key ends up in a public repo, so use a mailbox made for testing.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 rsa|p256|p384 test-mailbox@example.com" >&2
  exit 2
fi
NAME=$1
EMAIL=$2
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/crates/scomm-smime-cms/tests/fixtures/client-samples/identities"
mkdir -p "$OUT"
cd "$OUT"

case "$NAME" in
  rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$NAME.key" ;;
  p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$NAME.key" ;;
  p384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$NAME.key" ;;
  *) echo "unknown identity: $NAME" >&2; exit 2 ;;
esac

openssl req -x509 -new -key "$NAME.key" -days 3650 \
  -subj "/CN=$EMAIL" \
  -addext "subjectAltName=email:$EMAIL" \
  -addext "extendedKeyUsage=emailProtection" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyAgreement" \
  -out "$NAME.crt"
openssl pkcs8 -topk8 -nocrypt -in "$NAME.key" -outform DER -out "$NAME.p8"
openssl pkcs12 -export -inkey "$NAME.key" -in "$NAME.crt" -passout pass:interop -out "$NAME.p12"
rm "$NAME.key"
ls -1 "$NAME".*
