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
