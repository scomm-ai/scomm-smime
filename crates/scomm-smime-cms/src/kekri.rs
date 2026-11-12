//! Scomm KEM recipients carried in KEKRecipientInfo, as specified in
//! `design.md` ("Scomm KEM recipients in KEKRecipientInfo", R2 and R3).
//!
//! The F1 reader (D3) is live; the F1 writer runs only when
//! [crate::RELEASE_2_WRITERS] is on (Release 2) and in tests.
//!
//! - Content: RFC 5083 AuthEnvelopedData, AES-256-GCM, built by OpenSSL CMS.
//! - Recipient: KEKRecipientInfo whose `kekid.other` is
//!   `OtherKeyAttribute { scheme OID, ScommKemRecipient }`, and RSA
//!   KeyTransRecipientInfo with OAEP-SHA256 beside it.
//! - KEK: HKDF-SHA256 over the RFC 9629 `CMSORIforKEMOtherInfo`, then
//!   AES-256 key wrap by OpenSSL.
//! - X25519: RFC 9180 DHKEM through OpenSSL's EVP KEM.
//! - ML-KEM-768 + X25519: `id-MLKEM768-X25519-SHA3-256`,
//!   draft-ietf-lamps-pq-composite-kem-23, unmodified.

use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr};
use std::ptr;

use foreign_types::ForeignType;
use openssl::cms::CmsContentInfo;
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};
use openssl::md::Md;
use openssl::pkey::Id;
use openssl::pkey_ctx::{HkdfMode, PkeyCtx};
use openssl::rand::rand_bytes;
use openssl::x509::X509;
use openssl_sys as ffi;
use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::pkey::{EccData, EvpPkey, EvpPkeyType, PkeyData};
use ossl::{OsslContext, OsslParamBuilder, OsslSecret};
use scomm_smime_core::*;
use yasna::Tag;

use crate::bundle::{b64_decode, KeyBundle, KeyEntry};
use crate::cert::{x25519_dh, x25519_public};
use crate::cms_envelop::oid;
use crate::pqc;
use crate::reader::{ossl_failed, release_plaintext};

const OID_AUTH_ENVELOPED: &str = "1.2.840.113549.1.9.16.1.23";
const OID_AES256_WRAP: &str = "2.16.840.1.101.3.4.1.45";
const AES256_WRAP_ARCS: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 45];
const CMS_RECIPINFO_KEK: c_int = 2;
/// `CMS_KEY_PARAM` (`openssl/cms.h`): set the key transport parameters
/// before the recipient is encrypted.
const CMS_KEY_PARAM: c_uint = 0x40000;
const RSA_PKCS1_OAEP_PADDING: c_int = 4;
const KDF_LABEL: &str = "Scomm-CMS-KEKRI";
const VERSION: u64 = 1;
const KEK_ID_LEN: usize = 16;
const KEY_ID_LEN: usize = 32;
const X25519_LEN: usize = 32;
/// KEM combiner Label of `id-MLKEM768-X25519-SHA3-256` (draft -23, §6).
const COMPOSITE_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

// Present in the linked libcrypto but not bound by openssl-sys.
extern "C" {
    fn CMS_AuthEnvelopedData_create_ex(
        cipher: *const ffi::EVP_CIPHER,
        libctx: *mut c_void,
        propq: *const c_char,
    ) -> *mut ffi::CMS_ContentInfo;
    fn CMS_add0_recipient_key(
        cms: *mut ffi::CMS_ContentInfo,
        nid: c_int,
        key: *mut u8,
        keylen: usize,
        id: *mut u8,
        idlen: usize,
        date: *mut c_void,
        other_type_id: *mut ffi::ASN1_OBJECT,
        other_type: *mut ffi::ASN1_TYPE,
    ) -> *mut c_void;
    fn CMS_final(
        cms: *mut ffi::CMS_ContentInfo,
        data: *mut ffi::BIO,
        dcont: *mut ffi::BIO,
        flags: c_uint,
    ) -> c_int;
    fn CMS_add1_recipient_cert(
        cms: *mut ffi::CMS_ContentInfo,
        recip: *mut ffi::X509,
        flags: c_uint,
    ) -> *mut c_void;
    fn CMS_RecipientInfo_get0_pkey_ctx(ri: *mut c_void) -> *mut ffi::EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut ffi::EVP_PKEY_CTX, pad: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut ffi::EVP_PKEY_CTX, md: *const ffi::EVP_MD) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut ffi::EVP_PKEY_CTX, md: *const ffi::EVP_MD) -> c_int;
    fn CMS_set_detached(cms: *mut ffi::CMS_ContentInfo, detached: c_int) -> c_int;
    fn CMS_get0_type(cms: *const ffi::CMS_ContentInfo) -> *const ffi::ASN1_OBJECT;
    fn CMS_get0_RecipientInfos(cms: *mut ffi::CMS_ContentInfo) -> *mut ffi::OPENSSL_STACK;
    fn CMS_RecipientInfo_type(ri: *mut c_void) -> c_int;
    fn CMS_RecipientInfo_kekri_get0_id(
        ri: *mut c_void,
        palg: *mut *mut ffi::X509_ALGOR,
        pid: *mut *mut ffi::ASN1_STRING,
        pdate: *mut *mut c_void,
        potherid: *mut *mut ffi::ASN1_OBJECT,
        pothertype: *mut *mut ffi::ASN1_TYPE,
    ) -> c_int;
    fn CMS_RecipientInfo_set0_key(ri: *mut c_void, key: *mut u8, keylen: usize) -> c_int;
    fn CMS_RecipientInfo_decrypt(cms: *mut ffi::CMS_ContentInfo, ri: *mut c_void) -> c_int;
    fn i2d_ASN1_OBJECT(a: *const ffi::ASN1_OBJECT, pp: *mut *mut u8) -> c_int;
    fn CRYPTO_clear_free(ptr: *mut c_void, num: usize, file: *const c_char, line: c_int);
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
    fn BIO_free(b: *mut ffi::BIO) -> c_int;
}

/// A 32-byte secret wiped when dropped.
struct Secret([u8; 32]);

impl Drop for Secret {
    fn drop(&mut self) {
        unsafe { OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}

impl Secret {
    fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut s = Secret([0u8; 32]);
        if bytes.len() != s.0.len() {
            return Err(SmimeError::DecryptionFailed);
        }
        s.0.copy_from_slice(bytes);
        Ok(s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    X25519,
    MlKem768X25519,
}

impl Scheme {
    pub(crate) const ALL: [Scheme; 2] = [Scheme::X25519, Scheme::MlKem768X25519];

    /// The scheme a `kekid.other` OID names; unknown OIDs are not ours.
    fn from_oid_text(text: &str) -> Option<Scheme> {
        Scheme::ALL
            .into_iter()
            .find(|s| s.oid().to_str() == Ok(text))
    }

    /// Which bundle entries hold keys for this scheme.
    fn matches_entry(self, alg: &str) -> bool {
        match self {
            Scheme::X25519 => alg == ALG_X25519,
            Scheme::MlKem768X25519 => is_pqc_catalog(alg),
        }
    }

    fn algorithm(self) -> &'static str {
        match self {
            Scheme::X25519 => ALG_X25519,
            Scheme::MlKem768X25519 => ALG_MLKEM_HYBRID,
        }
    }

    /// Permanent UUIDv4-based scheme identifiers under ITU-T X.667's `2.25` arc.
    fn oid(self) -> &'static CStr {
        match self {
            Scheme::X25519 => c"2.25.39655194209308751609602662857696538149",
            Scheme::MlKem768X25519 => c"2.25.90424534707360863475365937468274977390",
        }
    }

    fn ciphertext_len(self) -> usize {
        match self {
            Scheme::X25519 => X25519_LEN,
            Scheme::MlKem768X25519 => pqc::MLKEM_CT_LEN + X25519_LEN,
        }
    }

    /// Scheme OID as an OpenSSL object the caller owns.
    fn object(self) -> Result<*mut ffi::ASN1_OBJECT> {
        let obj = unsafe { ffi::OBJ_txt2obj(self.oid().as_ptr(), 1) };
        if obj.is_null() {
            return Err(ossl_failed(SmimeError::Internal("scheme OID".into())));
        }
        Ok(obj)
    }

    fn der(self) -> Result<Vec<u8>> {
        let obj = self.object()?;
        unsafe {
            let len = i2d_ASN1_OBJECT(obj, ptr::null_mut());
            let mut out = vec![0u8; len.max(0) as usize];
            let mut p = out.as_mut_ptr();
            let written = i2d_ASN1_OBJECT(obj, &mut p);
            ffi::ASN1_OBJECT_free(obj);
            if len <= 0 || written != len {
                return Err(ossl_failed(SmimeError::Internal("scheme OID DER".into())));
            }
            Ok(out)
        }
    }
}

fn sha256(data: &[u8]) -> Result<[u8; KEY_ID_LEN]> {
    let d = hash(MessageDigest::sha256(), data).map_err(|e| SmimeError::Internal(e.to_string()))?;
    let mut out = [0u8; KEY_ID_LEN];
    out.copy_from_slice(&d);
    Ok(out)
}

/// `DER(CMSORIforKEMOtherInfo)` with `ukm = DER(ScommKekUkm)` (RFC 9629 §5).
/// `kekId` is SIZE(16) and `recipientKeyId` SIZE(32); anything else is refused.
fn kdf_info(scheme: Scheme, kek_id: &[u8], recipient_key_id: &[u8]) -> Result<Vec<u8>> {
    if kek_id.len() != KEK_ID_LEN || recipient_key_id.len() != KEY_ID_LEN {
        return Err(SmimeError::MalformedMessage);
    }
    let scheme_der = scheme.der()?;
    let ukm = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_utf8_string(KDF_LABEL);
            w.next().write_der(&scheme_der);
            w.next().write_u64(VERSION);
            w.next().write_bytes(kek_id);
            w.next().write_bytes(recipient_key_id);
        })
    });
    Ok(yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next()
                .write_sequence(|w| w.next().write_oid(&oid(AES256_WRAP_ARCS)));
            w.next().write_u64(32);
            w.next()
                .write_tagged(Tag::context(0), |w| w.write_bytes(&ukm));
        })
    }))
}

fn hkdf_sha256(ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let mut run = || -> std::result::Result<(), ErrorStack> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_md(Md::sha256())?;
        ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)?;
        ctx.set_hkdf_key(ikm)?;
        ctx.add_hkdf_info(info)?;
        ctx.derive(Some(out))?;
        Ok(())
    };
    run().map_err(|e| SmimeError::Internal(e.to_string()))
}

/// `KEK = HKDF-SHA256(IKM = ss, salt = empty, info = DER(CMSORIforKEMOtherInfo), L = 32)`.
fn derive_kek(
    ss: &Secret,
    scheme: Scheme,
    kek_id: &[u8],
    recipient_key_id: &[u8],
) -> Result<Secret> {
    let mut kek = Secret([0u8; 32]);
    hkdf_sha256(
        &ss.0,
        &kdf_info(scheme, kek_id, recipient_key_id)?,
        &mut kek.0,
    )?;
    Ok(kek)
}

/// DHKEM operation parameters. `ikme` fixes the ephemeral key and exists only
/// for the RFC 9180 known-answer tests.
fn dhkem_params(ikme: Option<&[u8]>) -> Result<ossl::OsslParam<'_>> {
    let internal = |e: ossl::Error| SmimeError::Internal(e.to_string());
    let mut p = OsslParamBuilder::new();
    p.add_const_c_string(c"operation", c"DHKEM")
        .map_err(internal)?;
    if let Some(ikme) = ikme {
        p.add_octet_slice(c"ikme", ikme).map_err(internal)?;
    }
    Ok(p.finalize())
}

/// DER prefix of an X25519 SubjectPublicKeyInfo (RFC 8410), 12 bytes.
const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

/// Recipient public key: exactly 32 raw bytes or exactly an RFC 8410 SPKI.
fn x25519_recipient_raw(public: &[u8]) -> Result<[u8; X25519_LEN]> {
    let raw = match public.len() {
        X25519_LEN => public,
        44 if public.starts_with(&X25519_SPKI_PREFIX) => &public[12..],
        _ => return Err(SmimeError::InvalidKey("X25519 public".into())),
    };
    Ok(raw.try_into().expect("length checked"))
}

/// RFC 9180 DHKEM(X25519, HKDF-SHA256) Encap: `(shared_secret, enc)`.
fn x25519_encaps(public: &[u8]) -> Result<(Secret, Vec<u8>)> {
    x25519_encaps_with(public, None)
}

fn x25519_encaps_with(public: &[u8], ikme: Option<&[u8]>) -> Result<(Secret, Vec<u8>)> {
    let c = OsslContext::new_lib_ctx();
    let raw = x25519_recipient_raw(public)?;
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::X25519,
        PkeyData::Ecc(EccData {
            pubkey: Some(raw.to_vec()),
            prikey: None,
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("X25519 public".into()))?;
    let params = dhkem_params(ikme)?;
    let mut op = OsslAsymcipher::new(&c, EncOp::Encapsulate, &mut key, Some(&params))
        .map_err(|_| ossl_failed(SmimeError::Internal("DHKEM init".into())))?;
    let mut enc = vec![0u8; X25519_LEN];
    let (ss, n) = op
        .encapsulate(&mut enc)
        .map_err(|_| ossl_failed(SmimeError::Internal("DHKEM encapsulate".into())))?;
    enc.truncate(n);
    Ok((Secret::from_slice(&ss)?, enc))
}

/// RFC 9180 DHKEM(X25519, HKDF-SHA256) Decap.
fn x25519_decaps(seed: &[u8], enc: &[u8]) -> Result<Secret> {
    let c = OsslContext::new_lib_ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::X25519,
        PkeyData::Ecc(EccData {
            pubkey: None,
            prikey: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("X25519 seed".into()))?;
    let params = dhkem_params(None)?;
    let mut op = OsslAsymcipher::new(&c, EncOp::Decapsulate, &mut key, Some(&params))
        .map_err(|_| ossl_failed(SmimeError::Internal("DHKEM init".into())))?;
    let ss = op
        .decapsulate(enc)
        .map_err(|_| ossl_failed(SmimeError::DecryptionFailed))?;
    Secret::from_slice(&ss)
}

/// `ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)` (draft -23, §3.4).
fn composite_combiner(
    mlkem_ss: &[u8],
    trad_ss: &[u8],
    trad_ct: &[u8],
    trad_pk: &[u8],
) -> Result<Secret> {
    let mut input = Vec::with_capacity(32 + 32 + 32 + 32 + COMPOSITE_LABEL.len());
    for part in [mlkem_ss, trad_ss, trad_ct, trad_pk, &COMPOSITE_LABEL[..]] {
        input.extend_from_slice(part);
    }
    let d =
        hash(MessageDigest::sha3_256(), &input).map_err(|e| SmimeError::Internal(e.to_string()));
    unsafe { OPENSSL_cleanse(input.as_mut_ptr().cast(), input.len()) };
    Secret::from_slice(&d?)
}

/// `id-MLKEM768-X25519-SHA3-256` Encaps (draft -23, §3.2). `public` is the
/// stored hybrid key `ek (1184) || X25519 public (32)`.
fn hybrid_encaps(public: &[u8]) -> Result<(Secret, Vec<u8>)> {
    if public.len() != pqc::MLKEM_EK_LEN + X25519_LEN {
        return Err(SmimeError::InvalidKey("hybrid public key".into()));
    }
    let (ek, trad_pk) = public.split_at(pqc::MLKEM_EK_LEN);
    let trad_pk: [u8; 32] = trad_pk
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("X25519".into()))?;
    let (mut ct, mlkem_ss) = pqc::mlkem_encaps(ek)?;
    let mlkem_ss = Secret(mlkem_ss);
    let mut eph = Secret([0u8; 32]);
    rand_bytes(&mut eph.0).map_err(|e| SmimeError::Internal(e.to_string()))?;
    let trad_ct = x25519_public(&eph.0)?;
    let trad_ss = Secret(x25519_dh(&eph.0, &trad_pk)?);
    let ss = composite_combiner(&mlkem_ss.0, &trad_ss.0, &trad_ct, &trad_pk)?;
    ct.extend_from_slice(&trad_ct);
    Ok((ss, ct))
}

/// `id-MLKEM768-X25519-SHA3-256` Decaps (draft -23, §3.3). `secret` is
/// `ML-KEM seed (64) || X25519 private (32)`; `tradPK` comes from our own
/// stored public key (§10.4).
fn hybrid_decaps(secret: &[u8], public: &[u8], ct: &[u8]) -> Result<Secret> {
    if secret.len() != pqc::MLKEM_SEED_LEN + 32 || public.len() != pqc::MLKEM_EK_LEN + X25519_LEN {
        return Err(SmimeError::InvalidKey("hybrid key".into()));
    }
    if ct.len() != Scheme::MlKem768X25519.ciphertext_len() {
        return Err(SmimeError::MalformedMessage);
    }
    let (mlkem_ct, trad_ct) = ct.split_at(pqc::MLKEM_CT_LEN);
    let trad_ct: [u8; 32] = trad_ct
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let mlkem_ss = Secret(pqc::mlkem_decaps(&secret[..pqc::MLKEM_SEED_LEN], mlkem_ct)?);
    let trad_ss = Secret(x25519_dh(&secret[pqc::MLKEM_SEED_LEN..], &trad_ct)?);
    composite_combiner(
        &mlkem_ss.0,
        &trad_ss.0,
        &trad_ct,
        &public[pqc::MLKEM_EK_LEN..],
    )
}

/// `ScommKemRecipient ::= SEQUENCE { version INTEGER (1), recipientKeyId OCTET STRING (SIZE(32)), kemCiphertext OCTET STRING }`
fn recipient_attr(recipient_key_id: &[u8], kem_ciphertext: &[u8]) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u64(VERSION);
            w.next().write_bytes(recipient_key_id);
            w.next().write_bytes(kem_ciphertext);
        })
    })
}

fn parse_recipient_attr(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (version, key_id, ct) = yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            Ok((
                r.next().read_u64()?,
                r.next().read_bytes()?,
                r.next().read_bytes()?,
            ))
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)?;
    if version != VERSION || key_id.len() != KEY_ID_LEN {
        return Err(SmimeError::MalformedMessage);
    }
    Ok((key_id, ct))
}

/// Copy into memory OpenSSL may free with `OPENSSL_clear_free`.
fn openssl_copy(bytes: &[u8]) -> Result<*mut u8> {
    let p = unsafe { ffi::CRYPTO_malloc(bytes.len(), c"kekri".as_ptr(), 0) } as *mut u8;
    if p.is_null() {
        return Err(SmimeError::Internal("out of memory".into()));
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
    Ok(p)
}

unsafe fn openssl_clear_free(p: *mut u8, len: usize) {
    if !p.is_null() {
        CRYPTO_clear_free(p.cast(), len, c"kekri".as_ptr(), 0);
    }
}

fn oid_text(obj: *const ffi::ASN1_OBJECT) -> String {
    if obj.is_null() {
        return String::new();
    }
    let mut buf = [0u8; 128];
    let n =
        unsafe { ffi::OBJ_obj2txt(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int, obj, 1) };
    let n = (n.max(0) as usize).min(buf.len() - 1);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Scheme of a KEKRecipientInfo, from `kekid.other.keyAttrId`; `None` for
/// any recipient that is not a Scomm KEM KEKRI (R8: structural routing).
pub(crate) unsafe fn kek_scheme(ri: *mut c_void) -> Option<Scheme> {
    let (mut alg, mut id, mut date, mut other_id, mut other) = (
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    if CMS_RecipientInfo_type(ri) != CMS_RECIPINFO_KEK
        || CMS_RecipientInfo_kekri_get0_id(
            ri,
            &mut alg,
            &mut id,
            &mut date,
            &mut other_id,
            &mut other,
        ) != 1
    {
        let _ = ErrorStack::get();
        return None;
    }
    Scheme::from_oid_text(&oid_text(other_id))
}

pub(crate) struct Recipient<'a> {
    pub scheme: Scheme,
    /// The recipient key exactly as stored (`spki_b64` decoded).
    pub public: &'a [u8],
}

/// What a writer put into one recipient; the spike tests use it to export the
/// KEK to the OpenSSL CLI and to find fields to tamper with.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Written {
    pub kek: [u8; 32],
    pub kek_id: [u8; KEK_ID_LEN],
    pub kem_ciphertext: Vec<u8>,
}

fn add_recipient(cms: &CmsContentInfo, r: &Recipient) -> Result<Written> {
    let (ss, kem_ciphertext) = match r.scheme {
        Scheme::X25519 => x25519_encaps(r.public)?,
        Scheme::MlKem768X25519 => hybrid_encaps(r.public)?,
    };
    let mut kek_id = [0u8; KEK_ID_LEN];
    rand_bytes(&mut kek_id).map_err(|e| SmimeError::Internal(e.to_string()))?;
    let recipient_key_id = sha256(r.public)?;
    let kek = derive_kek(&ss, r.scheme, &kek_id, &recipient_key_id)?;
    let attr = recipient_attr(&recipient_key_id, &kem_ciphertext);
    unsafe {
        let key = openssl_copy(&kek.0)?;
        let id = openssl_copy(&kek_id)?;
        let other_id = r.scheme.object().unwrap_or(ptr::null_mut());
        let mut p = attr.as_ptr();
        let other = ffi::d2i_ASN1_TYPE(ptr::null_mut(), &mut p, attr.len() as c_long);
        let ri = if other_id.is_null() || other.is_null() {
            ptr::null_mut()
        } else {
            // NID_undef: OpenSSL picks id-aes256-wrap for a 32-byte KEK.
            CMS_add0_recipient_key(
                cms.as_ptr(),
                0,
                key,
                32,
                id,
                KEK_ID_LEN,
                ptr::null_mut(),
                other_id,
                other,
            )
        };
        if ri.is_null() {
            // Ownership passes to OpenSSL only on success.
            openssl_clear_free(key, 32);
            openssl_clear_free(id, KEK_ID_LEN);
            if !other_id.is_null() {
                ffi::ASN1_OBJECT_free(other_id);
            }
            if !other.is_null() {
                ffi::ASN1_TYPE_free(other);
            }
            return Err(ossl_failed(SmimeError::Internal("KEK recipient".into())));
        }
    }
    Ok(Written {
        kek: kek.0,
        kek_id,
        kem_ciphertext,
    })
}

/// RSA KeyTransRecipientInfo with RSAES-OAEP, SHA-256 and MGF1-SHA-256,
/// empty label (`design.md` "Content encryption").
unsafe fn add_rsa_recipient(cms: &CmsContentInfo, cert: &X509) -> Result<()> {
    let ri = CMS_add1_recipient_cert(cms.as_ptr(), cert.as_ptr(), CMS_KEY_PARAM);
    if ri.is_null() {
        return Err(ossl_failed(SmimeError::InvalidKey(
            "RSA certificate".into(),
        )));
    }
    let ctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if ctx.is_null()
        || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0
        || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, ffi::EVP_sha256()) <= 0
        || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, ffi::EVP_sha256()) <= 0
    {
        return Err(ossl_failed(SmimeError::Internal("RSA recipient".into())));
    }
    Ok(())
}

/// AuthEnvelopedData (AES-256-GCM) with one KEKRecipientInfo per Scomm KEM
/// recipient and one KeyTransRecipientInfo per RSA certificate.
pub(crate) fn encrypt(
    plaintext: &[u8],
    recipients: &[Recipient],
    rsa: &[X509],
) -> Result<(Vec<u8>, Vec<Written>)> {
    let len = c_int::try_from(plaintext.len())
        .map_err(|_| SmimeError::InvalidArgument("message too large".into()))?;
    unsafe {
        let raw =
            CMS_AuthEnvelopedData_create_ex(ffi::EVP_aes_256_gcm(), ptr::null_mut(), ptr::null());
        if raw.is_null() {
            return Err(ossl_failed(SmimeError::Internal(
                "AuthEnvelopedData".into(),
            )));
        }
        let cms = CmsContentInfo::from_ptr(raw);
        // A new AuthEnvelopedData is detached by default; carry the content.
        if CMS_set_detached(cms.as_ptr(), 0) != 1 {
            return Err(ossl_failed(SmimeError::Internal("CMS_set_detached".into())));
        }
        let written = recipients
            .iter()
            .map(|r| add_recipient(&cms, r))
            .collect::<Result<Vec<_>>>()?;
        for cert in rsa {
            add_rsa_recipient(&cms, cert)?;
        }
        let input = ffi::BIO_new_mem_buf(plaintext.as_ptr().cast(), len);
        if input.is_null() {
            return Err(ossl_failed(SmimeError::Internal("BIO".into())));
        }
        let ok = CMS_final(cms.as_ptr(), input, ptr::null_mut(), ffi::CMS_BINARY);
        BIO_free(input);
        if ok != 1 {
            return Err(ossl_failed(SmimeError::Internal("CMS_final".into())));
        }
        let der = cms
            .to_der()
            .map_err(|e| SmimeError::Internal(e.to_string()))?;
        Ok((der, written))
    }
}

/// D3: tries one KEKRecipientInfo. On success the content key is set on `cms`.
unsafe fn open_recipient(
    cms: &CmsContentInfo,
    ri: *mut c_void,
    scheme: Scheme,
    my_key_id: &[u8],
    public: &[u8],
    secret: &[u8],
) -> Result<()> {
    let (mut alg, mut id, mut date, mut other_id, mut other) = (
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    if CMS_RecipientInfo_kekri_get0_id(ri, &mut alg, &mut id, &mut date, &mut other_id, &mut other)
        != 1
    {
        return Err(ossl_failed(SmimeError::MalformedMessage));
    }
    // Unknown schemes are skipped, not errors.
    if other_id.is_null()
        || other.is_null()
        || oid_text(other_id) != scheme.oid().to_str().unwrap_or("")
    {
        return Err(SmimeError::WrongPrivateKey);
    }
    let mut wrap: *const ffi::ASN1_OBJECT = ptr::null();
    ffi::X509_ALGOR_get0(&mut wrap, ptr::null_mut(), ptr::null_mut(), alg);
    if oid_text(wrap) != OID_AES256_WRAP || !date.is_null() {
        return Err(SmimeError::MalformedMessage);
    }
    let id_len = ffi::ASN1_STRING_length(id);
    if id_len != KEK_ID_LEN as c_int {
        return Err(SmimeError::MalformedMessage);
    }
    let kek_id = std::slice::from_raw_parts(ffi::ASN1_STRING_get0_data(id), KEK_ID_LEN).to_vec();
    let attr_len = ffi::i2d_ASN1_TYPE(other, ptr::null_mut());
    if attr_len <= 0 {
        return Err(ossl_failed(SmimeError::MalformedMessage));
    }
    let mut attr = vec![0u8; attr_len as usize];
    let mut p = attr.as_mut_ptr();
    ffi::i2d_ASN1_TYPE(other, &mut p);
    let (key_id, ct) = parse_recipient_attr(&attr)?;
    if key_id != my_key_id {
        return Err(SmimeError::WrongPrivateKey);
    }
    if ct.len() != scheme.ciphertext_len() {
        return Err(SmimeError::MalformedMessage);
    }
    let ss = match scheme {
        Scheme::X25519 => x25519_decaps(secret, &ct)?,
        Scheme::MlKem768X25519 => hybrid_decaps(secret, public, &ct)?,
    };
    let kek = derive_kek(&ss, scheme, &kek_id, my_key_id)?;
    let key = openssl_copy(&kek.0)?;
    if CMS_RecipientInfo_set0_key(ri, key, 32) != 1 {
        openssl_clear_free(key, 32);
        return Err(ossl_failed(SmimeError::Internal("set0_key".into())));
    }
    // AES key unwrap checks its integrity value here.
    if CMS_RecipientInfo_decrypt(cms.as_ptr(), ri) != 1 {
        return Err(ossl_failed(SmimeError::WrongPrivateKey));
    }
    Ok(())
}

/// D5: decrypt into a memory BIO and hand out the bytes only when OpenSSL
/// reports success (tag verified). The buffer is cleansed either way.
/// Opens AuthEnvelopedData for one of our Scomm KEM keys.
pub(crate) fn decrypt(der: &[u8], scheme: Scheme, public: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    let cms = CmsContentInfo::from_der(der).map_err(|_| SmimeError::MalformedMessage)?;
    unsafe {
        if oid_text(CMS_get0_type(cms.as_ptr())) != OID_AUTH_ENVELOPED {
            return Err(SmimeError::MalformedMessage);
        }
        let my_key_id = sha256(public)?;
        let stack = CMS_get0_RecipientInfos(cms.as_ptr());
        if stack.is_null() {
            return Err(ossl_failed(SmimeError::MalformedMessage));
        }
        let mut opened = false;
        for i in 0..ffi::OPENSSL_sk_num(stack) {
            let ri = ffi::OPENSSL_sk_value(stack, i);
            if CMS_RecipientInfo_type(ri) == CMS_RECIPINFO_KEK
                && open_recipient(&cms, ri, scheme, &my_key_id, public, secret).is_ok()
            {
                opened = true;
                break;
            }
        }
        if !opened {
            return Err(SmimeError::WrongPrivateKey);
        }
        release_plaintext(&cms)
    }
}

/// F1 writer over the recipient entries the engine selected.
pub(crate) fn encrypt_entries(plaintext: &[u8], entries: &[&KeyEntry]) -> Result<Vec<u8>> {
    let mut publics = Vec::new();
    let mut rsa = Vec::new();
    for e in entries {
        if let Some(scheme) = Scheme::ALL.into_iter().find(|s| s.matches_entry(&e.alg)) {
            publics.push((scheme, b64_decode(&e.spki_b64)?));
        } else if e.alg.contains("rsa") && !e.cert_pem.is_empty() {
            rsa.push(
                X509::from_pem(e.cert_pem.as_bytes())
                    .map_err(|_| ossl_failed(SmimeError::InvalidKey("X.509".into())))?,
            );
        } else {
            return Err(SmimeError::NoSuitableEncryptionKey);
        }
    }
    let recipients: Vec<Recipient> = publics
        .iter()
        .map(|(scheme, public)| Recipient {
            scheme: *scheme,
            public,
        })
        .collect();
    Ok(encrypt(plaintext, &recipients, &rsa)?.0)
}

/// D3/D4 over a secret bundle: every entry whose scheme appears among the
/// message's recipients is tried; a failing one does not stop the next.
pub(crate) fn decrypt_with_bundle(
    der: &[u8],
    schemes: &[Scheme],
    bundle: &KeyBundle,
) -> Result<DecryptResult> {
    let mut failure = SmimeError::WrongPrivateKey;
    for scheme in Scheme::ALL.into_iter().filter(|s| schemes.contains(s)) {
        for e in bundle
            .encryption_entries()
            .filter(|e| scheme.matches_entry(&e.alg))
        {
            let Some(secret) = e.pkcs8_b64.as_ref() else {
                continue;
            };
            let opened = b64_decode(&e.spki_b64)
                .and_then(|public| decrypt(der, scheme, &public, &b64_decode(secret)?));
            match opened {
                Ok(plaintext) => {
                    return Ok(DecryptResult {
                        plaintext,
                        algorithm: scheme.algorithm().to_string(),
                        format: FORMAT_F1.to_string(),
                    })
                }
                Err(SmimeError::WrongPrivateKey) => {}
                Err(e) => failure = e,
            }
        }
    }
    Err(failure)
}

#[cfg(test)]
mod tests;
