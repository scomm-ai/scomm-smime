mod bundle;
mod cert;
mod cms_envelop;
mod pqc;

use scomm_smime_core::*;

use bundle::KeyBundle;
use cert::{fingerprint_of, parse_email, rsa_encrypt_entry, rsa_sign_entry, x25519_encrypt_entry};
use cms_envelop::{
    decrypt_with_bundle, encrypt_to_entries, inspect_cms, maybe_pem_cms, pem_pkcs7, sign_mldsa,
    sign_pss, verify_signature,
};

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
            rsa_encrypt_entry(userid)?,
            x25519_encrypt_entry(),
            rsa_sign_entry(userid)?,
        ];
        if options.profile == KeyProfile::PqcCms {
            entries.push(pqc::hybrid_encrypt_entry()?);
            entries.push(pqc::mldsa_sign_entry()?);
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
        _options: &SignOptions,
    ) -> Result<Vec<u8>> {
        let bundle = KeyBundle::parse(private_key)?;
        if let Some(pqc_sign) = bundle
            .signing_entries()
            .find(|e| e.alg.eq_ignore_ascii_case(ALG_MLDSA65))
        {
            return sign_mldsa(data, pqc_sign);
        }
        let rsa = bundle
            .signing_entries()
            .find(|e| e.alg.contains("rsa"))
            .ok_or(SmimeError::NoSuitableSigningKey)?;
        sign_pss(data, rsa)
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

    fn encrypt(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        options: &EncryptOptions,
    ) -> Result<Vec<u8>> {
        let mut chosen: Vec<crate::bundle::KeyEntry> = Vec::new();
        let multi = recipient_public_keys.len() > 1;
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
            if multi {
                if let Some(rsa) = rsa {
                    chosen.push(rsa);
                } else if let Some(x) = x {
                    chosen.push(x);
                } else if let Some(pqc) = pqc {
                    chosen.push(pqc);
                }
            } else if let Some(pqc) = pqc {
                chosen.push(pqc);
            } else if let Some(rsa) = rsa {
                chosen.push(rsa);
            } else if let Some(x) = x {
                chosen.push(x);
            }
        }
        if chosen.is_empty() {
            return Err(SmimeError::NoSuitableEncryptionKey);
        }
        let refs: Vec<&crate::bundle::KeyEntry> = chosen.iter().collect();
        let der = encrypt_to_entries(plaintext, &refs)?;
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
        let der = maybe_pem_cms(message)?;
        inspect_cms(&der)
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
}
