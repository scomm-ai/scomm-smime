use serde::{Deserialize, Serialize};
use scomm_smime_core::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    pub v: u8,
    pub entries: Vec<KeyEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    pub alg: String,
    pub purpose: String,
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub spki_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs8_b64: Option<String>,
}

impl KeyBundle {
    pub fn to_public_json(&self) -> Result<Vec<u8>> {
        let public = KeyBundle {
            v: self.v,
            entries: self
                .entries
                .iter()
                .map(|e| KeyEntry {
                    alg: e.alg.clone(),
                    purpose: e.purpose.clone(),
                    cert_pem: e.cert_pem.clone(),
                    spki_b64: e.spki_b64.clone(),
                    pkcs8_b64: None,
                })
                .collect(),
        };
        serde_json::to_vec(&public)
            .map_err(|e| SmimeError::Internal(format!("json: {e}")))
    }

    pub fn to_secret_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| SmimeError::Internal(format!("json: {e}")))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if let Ok(bundle) = serde_json::from_slice::<KeyBundle>(bytes) {
            if bundle.v == 1 && !bundle.entries.is_empty() {
                return Ok(bundle);
            }
        }
        // Single PEM cert or PKCS#8 treated as a classical RSA blob.
        let text = String::from_utf8_lossy(bytes);
        if text.contains("BEGIN CERTIFICATE") || text.contains("BEGIN PRIVATE KEY") {
            return Ok(KeyBundle {
                v: 1,
                entries: vec![KeyEntry {
                    alg: ALG_RSA_OAEP.to_string(),
                    purpose: "encryption".into(),
                    cert_pem: text.to_string(),
                    spki_b64: String::new(),
                    pkcs8_b64: if text.contains("BEGIN PRIVATE KEY") {
                        Some(b64_encode(bytes))
                    } else {
                        None
                    },
                }],
            });
        }
        Err(SmimeError::InvalidKey("not an S/MIME key bundle".into()))
    }

    pub fn encryption_entries(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.iter().filter(|e| e.purpose == "encryption")
    }

    pub fn signing_entries(&self) -> impl Iterator<Item = &KeyEntry> {
        self.entries.iter().filter(|e| e.purpose == "signing")
    }
}

pub fn b64_encode(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.trim())
        .map_err(|_| SmimeError::InvalidKey("base64".into()))
}
