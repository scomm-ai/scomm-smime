# scomm-smime

Reusable S/MIME (CMS/X.509) SDK for Scomm.AI. The CMS engine is an implementation detail.

First-ship algorithms:

- Classical encrypt: `smime-rsa-oaep-sha256` and `smime-x25519` (dual-publish)
- Classical sign: `smime-rsa-pss-sha256`
- PQC encrypt: `smime-mlkem768-x25519`
- PQC sign: `pqc-mldsa65` (family `smime`)

RSA and ECC S/MIME are free in the Scomm.AI client. PQC decrypt/sign use the same `crypto` add-on as OpenPGP PQC.

```
crates/scomm-smime-core/   types + SmimeProvider
crates/scomm-smime-cms/    CMS engine
crates/scomm-smime-ffi/    C ABI (`scomm_smime`)
dart/scomm_smime/          Flutter FFI plugin
include/scomm_smime.h
```

### Classical NIST curves (ABI 8)

Profiles 4/5/6 select P-256/P-384/P-521 with separate ECDSA signing and ECDH encryption keys and certificates. Signing algorithm names are `smime-ecdsa-p256-sha256`, `smime-ecdsa-p384-sha384`, and `smime-ecdsa-p521-sha512`. Encryption entries use `smime-ecdh-p256`, `smime-ecdh-p384`, and `smime-ecdh-p521`. EC recipients use OpenSSL CMS KeyAgreeRecipientInfo (RFC 5753), curve-matched SHA-256/384/512 KDF, AES-256 key wrap and AES-256-GCM AuthEnvelopedData. Mixed RSA, X25519 and hybrid recipients remain supported. Existing profiles, defaults and the RSA CSR flow are unchanged. Dart exposes `supportsNistCurves` and corresponding `SmimeKeyProfile` values; older binaries are refused. App UI and directory integration are separate.
