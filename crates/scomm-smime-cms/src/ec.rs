//! Classical NIST profiles. All key, certificate and CMS crypto uses OpenSSL.
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, PKeyRef, Private};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509NameBuilder, X509};
use scomm_smime_core::*;

use crate::bundle::{b64_decode, b64_encode, KeyEntry};
use crate::cert::{parse_email, validity_window};
use crate::reader::ossl_failed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    pub(crate) fn signing(self) -> &'static str {
        match self {
            Self::P256 => ALG_ECDSA_P256,
            Self::P384 => ALG_ECDSA_P384,
            Self::P521 => ALG_ECDSA_P521,
        }
    }

    fn encryption(self) -> &'static str {
        match self {
            Self::P256 => ALG_ECDH_P256,
            Self::P384 => ALG_ECDH_P384,
            Self::P521 => ALG_ECDH_P521,
        }
    }

    pub(crate) fn from_encryption(alg: &str) -> Option<Self> {
        match alg {
            ALG_ECDH_P256 => Some(Self::P256),
            ALG_ECDH_P384 => Some(Self::P384),
            ALG_ECDH_P521 => Some(Self::P521),
            _ => None,
        }
    }

    fn nid(self) -> Nid {
        match self {
            Self::P256 => Nid::X9_62_PRIME256V1,
            Self::P384 => Nid::SECP384R1,
            Self::P521 => Nid::SECP521R1,
        }
    }

    pub(crate) fn from_key<T: HasPublic>(key: &PKeyRef<T>) -> Result<Self> {
        let ec = key
            .ec_key()
            .map_err(|_| ossl_failed(SmimeError::InvalidKey("EC key".into())))?;
        match ec.group().curve_name() {
            Some(Nid::X9_62_PRIME256V1) => Ok(Self::P256),
            Some(Nid::SECP384R1) => Ok(Self::P384),
            Some(Nid::SECP521R1) => Ok(Self::P521),
            _ => Err(SmimeError::UnsupportedAlgorithm("EC curve".into())),
        }
    }

    pub(crate) fn digest(self) -> MessageDigest {
        match self {
            Self::P256 => MessageDigest::sha256(),
            Self::P384 => MessageDigest::sha384(),
            Self::P521 => MessageDigest::sha512(),
        }
    }
}

fn failed(e: openssl::error::ErrorStack) -> SmimeError {
    SmimeError::Internal(format!("EC: {e}"))
}

pub(crate) fn private_key(entry: &KeyEntry, curve: Curve) -> Result<PKey<Private>> {
    let der = b64_decode(
        entry
            .pkcs8_b64
            .as_deref()
            .ok_or(SmimeError::InvalidKey("missing EC key".into()))?,
    )?;
    let key = PKey::private_key_from_der(&der)
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("EC private key".into())))?;
    if Curve::from_key(&key)? != curve {
        return Err(SmimeError::InvalidKey(
            "EC curve does not match entry".into(),
        ));
    }
    Ok(key)
}

pub(crate) fn entries(userid: &str, curve: Curve, years: Option<u32>) -> Result<Vec<KeyEntry>> {
    Ok(vec![
        entry(userid, curve, years, true)?,
        entry(userid, curve, years, false)?,
    ])
}

fn entry(userid: &str, curve: Curve, years: Option<u32>, signing: bool) -> Result<KeyEntry> {
    let group = EcGroup::from_curve_name(curve.nid()).map_err(failed)?;
    let key = PKey::from_ec_key(EcKey::generate(&group).map_err(failed)?).map_err(failed)?;
    let email = parse_email(userid);
    let mut subject = X509NameBuilder::new().map_err(failed)?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, &email)
        .map_err(failed)?;
    let subject = subject.build();
    let mut cert = X509::builder().map_err(failed)?;
    cert.set_version(2).map_err(failed)?;
    let mut serial = BigNum::new().map_err(failed)?;
    serial.rand(159, MsbOption::ONE, false).map_err(failed)?;
    let serial = serial.to_asn1_integer().map_err(failed)?;
    cert.set_serial_number(&serial).map_err(failed)?;
    cert.set_subject_name(&subject).map_err(failed)?;
    cert.set_issuer_name(&subject).map_err(failed)?;
    cert.set_pubkey(&key).map_err(failed)?;
    let (start, end) = validity_window(years);
    let start = Asn1Time::from_str_x509(&start).map_err(failed)?;
    cert.set_not_before(&start).map_err(failed)?;
    let end = Asn1Time::from_str_x509(&end).map_err(failed)?;
    cert.set_not_after(&end).map_err(failed)?;
    cert.append_extension(BasicConstraints::new().critical().build().map_err(failed)?)
        .map_err(failed)?;
    let mut usage = KeyUsage::new();
    usage.critical();
    if signing {
        usage.digital_signature();
    } else {
        usage.key_agreement();
    }
    cert.append_extension(usage.build().map_err(failed)?)
        .map_err(failed)?;
    cert.append_extension(
        ExtendedKeyUsage::new()
            .email_protection()
            .build()
            .map_err(failed)?,
    )
    .map_err(failed)?;
    let san = SubjectAlternativeName::new()
        .email(&email)
        .build(&cert.x509v3_context(None, None))
        .map_err(failed)?;
    cert.append_extension(san).map_err(failed)?;
    cert.sign(&key, curve.digest()).map_err(failed)?;
    let cert = cert.build();
    if !cert.verify(&key).map_err(failed)? {
        return Err(SmimeError::Internal("EC certificate signature".into()));
    }
    Ok(KeyEntry {
        alg: if signing {
            curve.signing()
        } else {
            curve.encryption()
        }
        .into(),
        purpose: if signing { "signing" } else { "encryption" }.into(),
        cert_pem: String::from_utf8(cert.to_pem().map_err(failed)?)
            .map_err(|_| SmimeError::Internal("EC PEM".into()))?,
        spki_b64: b64_encode(&key.public_key_to_der().map_err(failed)?),
        pkcs8_b64: Some(b64_encode(&key.private_key_to_pkcs8().map_err(failed)?)),
        legacy_key_ids: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bundle::KeyBundle, cert::rsa_encrypt_entry, CmsSmime};

    #[test]
    fn ec_and_rsa_recipients_open_the_same_authenticated_message() {
        let engine = CmsSmime::new();
        let ec = engine
            .generate_key(&GenerateKeyOptions {
                userid: "ec@example.com".into(),
                profile: KeyProfile::ClassicalP256,
                ..Default::default()
            })
            .unwrap();
        let rsa = KeyBundle {
            v: 1,
            entries: vec![rsa_encrypt_entry("rsa@example.com").unwrap()],
        };
        let encrypted = engine
            .encrypt(
                b"mixed RSA and ECDH",
                &[&ec.public, &rsa.to_public_json().unwrap()],
                &EncryptOptions { armored: false },
            )
            .unwrap();
        for secret in [&ec.secret, &rsa.to_secret_json().unwrap()] {
            let opened = engine.decrypt(&encrypted, secret, None).unwrap();
            assert_eq!(opened.plaintext, b"mixed RSA and ECDH");
            assert_eq!(opened.format, FORMAT_F1);
        }
    }
}
