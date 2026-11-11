//! Structural identification of CMS input (R8).
//!
//! Routing never searches raw bytes for OID encodings. Standard CMS is parsed
//! by OpenSSL. The two shapes only older Scomm builds write, which OpenSSL
//! rejects, are parsed field by field in [crate::legacy].

use std::ffi::{c_char, c_int, c_void};

use foreign_types::ForeignType;
use openssl::cms::CmsContentInfo;
use scomm_smime_core::*;

use crate::kekri::{kek_scheme, Scheme};
use crate::legacy;

/// Largest CMS message (DER) the engine reads or writes: 128 MiB. Above
/// every provider's message cap once MIME and transfer encoding are counted
/// (Graph's 150 MB on the wire is about 105 MiB of DER), so any message a
/// supported mailbox delivers can be opened. The writers refuse to produce
/// more ([MAX_PLAINTEXT_LEN]), so nothing the app sends is unreadable.
pub const MAX_MESSAGE_LEN: usize = 128 << 20;

/// Largest plaintext the writers accept: [MAX_MESSAGE_LEN] less 1 MiB for
/// recipient infos and padding. The app checks this before it sends.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - (1 << 20);

/// Armored (PEM) input is base64, about 4/3 of the DER; bound it before
/// decoding, then check the DER itself.
const MAX_ARMORED_LEN: usize = MAX_MESSAGE_LEN / 3 * 4 + (1 << 20);

pub(crate) fn too_large() -> SmimeError {
    SmimeError::InvalidArgument(format!("message larger than {} MiB", MAX_MESSAGE_LEN >> 20))
}

const OID_ENVELOPED: &str = "1.2.840.113549.1.7.3";
const OID_AUTH_ENVELOPED: &str = "1.2.840.113549.1.9.16.1.23";
const OID_SIGNED: &str = "1.2.840.113549.1.7.2";
const OID_RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
/// `V_ASN1_UNDEF`: the AlgorithmIdentifier has no parameters field.
const PARAMETERS_ABSENT: c_int = -1;

/// `CMS_RECIPINFO_*` from `openssl/cms.h`.
const CMS_RECIPINFO_TRANS: c_int = 0;

// Present in the linked libcrypto but not bound by openssl-sys.
extern "C" {
    fn CMS_get0_type(cms: *const openssl_sys::CMS_ContentInfo) -> *const openssl_sys::ASN1_OBJECT;
    fn CMS_get0_RecipientInfos(
        cms: *mut openssl_sys::CMS_ContentInfo,
    ) -> *mut openssl_sys::OPENSSL_STACK;
    fn CMS_RecipientInfo_type(ri: *mut c_void) -> c_int;
    fn CMS_RecipientInfo_ktri_get0_algs(
        ri: *mut c_void,
        pk: *mut *mut c_void,
        recip: *mut *mut c_void,
        palg: *mut *mut openssl_sys::X509_ALGOR,
    ) -> c_int;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recipient {
    /// KeyTransRecipientInfo (RSA) that OpenSSL can open.
    KeyTransport,
    /// KeyTransRecipientInfo whose `rsaesOaep` parameters are absent, as
    /// older Scomm builds write it while actually using SHA-256. Standard
    /// encoders always write the parameters, and OpenSSL refuses the
    /// recipient without them (`rsa_oaep_decode` in `cms_rsa.c`).
    LegacyKeyTransport,
    /// KEKRecipientInfo carrying a Scomm KEM recipient (F1, D3).
    ScommKem(Scheme),
    /// Legacy Scomm OtherRecipientInfo `1.3.101.110`, XOR-wrapped CEK.
    LegacyX25519,
    /// Legacy Scomm OtherRecipientInfo `1.3.6.1.4.1.54392.1.1`, XOR-wrapped CEK.
    LegacyHybrid,
    /// Any other recipient type; nothing here can open it yet.
    Unsupported,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Enveloped {
        authenticated: bool,
        recipients: Vec<Recipient>,
    },
    /// RFC 5652 SignedData.
    Signed,
    /// Legacy Scomm `SEQUENCE { algorithm, data, signature }` (S0).
    LegacySigned {
        algorithm: &'static str,
    },
    Other,
}

pub(crate) struct Parsed {
    pub der: Vec<u8>,
    pub kind: Kind,
}

pub(crate) fn classify(input: &[u8]) -> Result<Parsed> {
    if input.len() > MAX_ARMORED_LEN {
        return Err(too_large());
    }
    let der = unarmor(input)?;
    if der.len() > MAX_MESSAGE_LEN {
        return Err(too_large());
    }
    let kind = match CmsContentInfo::from_der(&der) {
        Ok(cms) => standard_kind(&cms),
        Err(_) => legacy::classify(&der)?,
    };
    Ok(Parsed { der, kind })
}

/// PEM only when the input starts with an armor line; DER starts with 0x30.
pub(crate) fn unarmor(input: &[u8]) -> Result<Vec<u8>> {
    let start = input
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    if !input[start..].starts_with(b"-----BEGIN ") {
        return Ok(input.to_vec());
    }
    let p = ::pem::parse(&input[start..]).map_err(|_| SmimeError::MalformedMessage)?;
    match p.tag() {
        "PKCS7" | "CMS" => Ok(p.into_contents()),
        _ => Err(SmimeError::MalformedMessage),
    }
}

fn standard_kind(cms: &CmsContentInfo) -> Kind {
    let content_type = oid_text(unsafe { CMS_get0_type(cms.as_ptr()) });
    match content_type.as_str() {
        OID_ENVELOPED | OID_AUTH_ENVELOPED => Kind::Enveloped {
            authenticated: content_type == OID_AUTH_ENVELOPED,
            recipients: recipient_types(cms),
        },
        OID_SIGNED => Kind::Signed,
        _ => Kind::Other,
    }
}

fn recipient_types(cms: &CmsContentInfo) -> Vec<Recipient> {
    unsafe {
        let stack = CMS_get0_RecipientInfos(cms.as_ptr());
        if stack.is_null() {
            return Vec::new();
        }
        (0..openssl_sys::OPENSSL_sk_num(stack))
            .map(|i| {
                let ri = openssl_sys::OPENSSL_sk_value(stack, i);
                match CMS_RecipientInfo_type(ri) {
                    CMS_RECIPINFO_TRANS if is_legacy_oaep(ri) => Recipient::LegacyKeyTransport,
                    CMS_RECIPINFO_TRANS => Recipient::KeyTransport,
                    _ => kek_scheme(ri).map_or(Recipient::Unsupported, Recipient::ScommKem),
                }
            })
            .collect()
    }
}

unsafe fn is_legacy_oaep(ri: *mut c_void) -> bool {
    let mut alg: *mut openssl_sys::X509_ALGOR = std::ptr::null_mut();
    if CMS_RecipientInfo_ktri_get0_algs(ri, std::ptr::null_mut(), std::ptr::null_mut(), &mut alg)
        != 1
        || alg.is_null()
    {
        return false;
    }
    let mut obj: *const openssl_sys::ASN1_OBJECT = std::ptr::null();
    let mut ptype: c_int = 0;
    let mut pval: *const c_void = std::ptr::null();
    openssl_sys::X509_ALGOR_get0(&mut obj, &mut ptype, &mut pval, alg);
    ptype == PARAMETERS_ABSENT && oid_text(obj) == OID_RSAES_OAEP
}

fn oid_text(obj: *const openssl_sys::ASN1_OBJECT) -> String {
    if obj.is_null() {
        return String::new();
    }
    let mut buf = [0u8; 128];
    let n = unsafe {
        openssl_sys::OBJ_obj2txt(buf.as_mut_ptr() as *mut c_char, buf.len() as c_int, obj, 1)
    };
    let n = (n.max(0) as usize).min(buf.len() - 1);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}
