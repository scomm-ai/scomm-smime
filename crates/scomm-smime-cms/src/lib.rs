mod bundle;
mod cert;
mod certinfo;
mod classify;
mod cms_envelop;
mod kekri;
mod legacy;
mod legacy_writer;
mod pqc;
mod reader;
mod signed;
mod trust;

pub use certinfo::{cert_info, CertInfo};
pub use classify::{MAX_MESSAGE_LEN, MAX_PLAINTEXT_LEN};
pub use pqc::add_mldsa_certificates;
pub use trust::{check_certificate, set_trust_roots};

use scomm_smime_core::*;

use bundle::KeyBundle;
use cert::{ed25519_sign_entry, fingerprint_of, parse_email, x25519_encrypt_entry};
use cms_envelop::{
    decrypt_with_bundle, inspect_cms, pem_pkcs7, rsa_oaep_decrypt_raw, sign_pss_raw,
    verify_detached, verify_signature,
};
use legacy_writer::{encrypt_to_entries, sign_ed25519, sign_mldsa, sign_pss};
use signed::SignAlg;

/// Release 2 switch (`design.md` "Compatibility and rollout"). Off: new
/// messages stay F0-scomm and Ed25519, ML-DSA and RSA-PSS signatures stay
/// S0, so older app versions can read them. On: F1 encryption
/// (AuthEnvelopedData, RSA-OAEP-SHA256 KTRI and Scomm KEKRI) and S1
/// SignedData for every algorithm. Both writers ship either way and are
/// exercised by tests. RSA PKCS#1 v1.5 is S1 in both releases.
pub const RELEASE_2_WRITERS: bool = true;

pub struct CmsSmime;

impl CmsSmime {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CmsSmime {
    fn default() -> Self {
        Self::new()
    }
}

fn info_from_bundle(bundle: &KeyBundle, has_secret: bool) -> SmimeKeyInfo {
    let email = bundle.entries.iter().find_map(|e| {
        if e.cert_pem.is_empty() {
            None
        } else {
            Some(parse_email(&e.cert_pem))
        }
    });
    SmimeKeyInfo {
        identities: bundle
            .entries
            .iter()
            .map(|e| {
                let material = if !e.cert_pem.is_empty() {
                    e.cert_pem.as_bytes()
                } else {
                    e.spki_b64.as_bytes()
                };
                SmimeCertInfo {
                    fingerprint: fingerprint_of(material),
                    serial: fingerprint_of(material)[..16.min(fingerprint_of(material).len())]
                        .to_string(),
                    algorithm: e.alg.clone(),
                    email: email.clone(),
                    subject: email.clone().unwrap_or_default(),
                    not_before: 0,
                    not_after: 0,
                    usage: if e.purpose == "signing" {
                        KeyUsage::Signing
                    } else {
                        KeyUsage::Encryption
                    },
                    has_secret: has_secret && e.pkcs8_b64.is_some(),
                    pqc: is_pqc_catalog(&e.alg),
                    legacy_key_ids: e.legacy_key_ids.clone(),
                }
            })
            .collect(),
    }
}

impl SmimeProvider for CmsSmime {
    fn inspect_key(&self, key: &[u8]) -> Result<SmimeKeyInfo> {
        let bundle = KeyBundle::parse(key)?;
        let has_secret = bundle.entries.iter().any(|e| e.pkcs8_b64.is_some());
        Ok(info_from_bundle(&bundle, has_secret))
    }

    fn generate_key(&self, options: &GenerateKeyOptions) -> Result<GeneratedKey> {
        let userid = if options.userid.is_empty() {
            "user@localhost"
        } else {
            options.userid.as_str()
        };
        let mut entries = vec![
            x25519_encrypt_entry()?,
            ed25519_sign_entry(userid)?,
        ];
        if options.profile == KeyProfile::PqcCms {
            entries.push(pqc::hybrid_encrypt_entry()?);
            let email = parse_email(userid);
            entries.push(pqc::mldsa_sign_entry(
                Some(email.as_str()).filter(|e| e.contains('@')),
            )?);
        }
        let bundle = KeyBundle { v: 1, entries };
        let public = bundle.to_public_json()?;
        let secret = bundle.to_secret_json()?;
        Ok(GeneratedKey {
            public,
            secret,
            info: info_from_bundle(&bundle, true),
        })
    }

    fn export_public_key(&self, secret_or_public: &[u8]) -> Result<Vec<u8>> {
        KeyBundle::parse(secret_or_public)?.to_public_json()
    }

    fn sign(
        &self,
        data: &[u8],
        private_key: &[u8],
        _passphrase: Option<&str>,
        options: &SignOptions,
    ) -> Result<Vec<u8>> {
        let bundle = KeyBundle::parse(private_key)?;
        let alg = SignAlg::from_name(options.algorithm)
            .ok_or_else(|| SmimeError::UnsupportedAlgorithm(options.algorithm.to_string()))?;
        let entry = bundle
            .signing_entries()
            .find(|e| alg.matches_entry(&e.alg))
            .ok_or(SmimeError::NoSuitableSigningKey)?;
        match alg {
            SignAlg::RsaPkcs1 => signed::sign(data, entry, alg),
            _ if RELEASE_2_WRITERS => signed::sign(data, entry, alg),
            SignAlg::Ed25519 => sign_ed25519(data, entry),
            SignAlg::MlDsa65 => sign_mldsa(data, entry),
            SignAlg::RsaPss => sign_pss(data, entry),
        }
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<VerificationResult> {
        let bundle = KeyBundle::parse(public_key)?;
        verify_signature(data, signature, &bundle)
    }

    fn verify_detached(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: Option<&[u8]>,
        sender: Option<&str>,
    ) -> Result<SignatureVerdict> {
        let bundle = public_key.map(KeyBundle::parse).transpose()?;
        verify_detached(data, signature, bundle.as_ref(), sender)
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        options: &EncryptOptions,
    ) -> Result<Vec<u8>> {
        let mut chosen: Vec<crate::bundle::KeyEntry> = Vec::new();
        for pk in recipient_public_keys {
            let bundle = KeyBundle::parse(pk)?;
            let pqc = bundle
                .encryption_entries()
                .find(|e| e.alg.eq_ignore_ascii_case(ALG_MLKEM_HYBRID))
                .cloned();
            let rsa = bundle
                .encryption_entries()
                .find(|e| e.alg.contains("rsa-oaep") || e.alg.contains("rsa"))
                .cloned();
            let x = bundle
                .encryption_entries()
                .find(|e| e.alg.contains("x25519") && !e.alg.contains("mlkem"))
                .cloned();
            // A recipient with a post-quantum key never gets a classical copy:
            // one classical wrap of the CEK makes the whole message classical.
            if let Some(pqc) = pqc {
                chosen.push(pqc);
            } else if let Some(x) = x {
                chosen.push(x);
            } else if let Some(rsa) = rsa {
                chosen.push(rsa);
            }
        }
        if chosen.is_empty() {
            return Err(SmimeError::NoSuitableEncryptionKey);
        }
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(SmimeError::InvalidArgument(format!(
                "message larger than {} MiB",
                MAX_PLAINTEXT_LEN >> 20
            )));
        }
        let refs: Vec<&crate::bundle::KeyEntry> = chosen.iter().collect();
        let der = if RELEASE_2_WRITERS {
            kekri::encrypt_entries(plaintext, &refs)?
        } else {
            encrypt_to_entries(plaintext, &refs)?
        };
        // Many recipients could still push the envelope past what the
        // reader accepts; never hand out a message nobody can open.
        if der.len() > MAX_MESSAGE_LEN {
            return Err(classify::too_large());
        }
        if options.armored {
            Ok(pem_pkcs7(&der))
        } else {
            Ok(der)
        }
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        _passphrase: Option<&str>,
    ) -> Result<DecryptResult> {
        let bundle = KeyBundle::parse(private_key)?;
        decrypt_with_bundle(ciphertext, &bundle)
    }

    fn inspect_message(&self, message: &[u8]) -> Result<MessageInfo> {
        inspect_cms(message)
    }

    fn test_passphrase(&self, private_key: &[u8], _passphrase: Option<&str>) -> Result<()> {
        let bundle = KeyBundle::parse(private_key)?;
        if bundle.entries.iter().any(|e| e.pkcs8_b64.is_some()) {
            Ok(())
        } else {
            Err(SmimeError::InvalidKey("no secret".into()))
        }
    }

    fn pop_sign_mldsa(
        &self,
        data: &[u8],
        private_key: &[u8],
        _passphrase: Option<&str>,
    ) -> Result<Vec<u8>> {
        let bundle = KeyBundle::parse(private_key)?;
        let entry = bundle
            .signing_entries()
            .find(|e| is_pqc_catalog(&e.alg))
            .ok_or(SmimeError::NoSuitableSigningKey)?;
        pqc::sign_mldsa(data, entry)
    }

    fn pop_hybrid_shared(
        &self,
        private_key: &[u8],
        _passphrase: Option<&str>,
        kem_ciphertext: &[u8],
        ephemeral_x25519: &[u8],
    ) -> Result<Vec<u8>> {
        let bundle = KeyBundle::parse(private_key)?;
        let entry = bundle
            .encryption_entries()
            .find(|e| is_pqc_catalog(&e.alg))
            .ok_or(SmimeError::NoSuitableEncryptionKey)?;
        pqc::pop_hybrid(entry, kem_ciphertext, ephemeral_x25519)
    }

    fn pop_sign_classical(
        &self,
        data: &[u8],
        private_key: &[u8],
        _passphrase: Option<&str>,
    ) -> Result<Vec<u8>> {
        let bundle = KeyBundle::parse(private_key)?;
        let entry = bundle
            .signing_entries()
            .find(|e| e.alg.contains("rsa"))
            .ok_or(SmimeError::NoSuitableSigningKey)?;
        sign_pss_raw(data, entry)
    }

    fn pop_rsa_decrypt(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        _passphrase: Option<&str>,
    ) -> Result<Vec<u8>> {
        let bundle = KeyBundle::parse(private_key)?;
        let entry = bundle
            .encryption_entries()
            .find(|e| e.alg.contains("rsa"))
            .ok_or(SmimeError::NoSuitableEncryptionKey)?;
        rsa_oaep_decrypt_raw(ciphertext, entry)
    }
}
