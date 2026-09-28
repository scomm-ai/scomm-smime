use openssl::hash::{hash, MessageDigest};
use openssl::rand::rand_bytes;
use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::signature::{OsslSignature, SigAlg, SigOp};
use ossl::OsslSecret;
use scomm_smime_core::*;

use crate::bundle::{b64_decode, b64_encode, KeyEntry};
use crate::cert::{x25519_dh, x25519_public, x25519_raw_from_spki_or_raw};
use crate::cms_envelop::{aes_decrypt_pub, extract_ori_iv_ct, extract_ori_payload};

const MLKEM_CT_LEN: usize = 1088;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_SEED_LEN: usize = 64;

fn ctx() -> ossl::OsslContext {
    ossl::OsslContext::new_lib_ctx()
}

fn sha256_32(data: &[u8]) -> Result<[u8; 32]> {
    let dig = hash(MessageDigest::sha256(), data).map_err(|e| SmimeError::Internal(e.to_string()))?;
    let bytes: [u8; 32] = dig
        .as_ref()
        .try_into()
        .map_err(|_| SmimeError::Internal("sha256".into()))?;
    Ok(bytes)
}

fn random(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    rand_bytes(&mut buf).map_err(|e| SmimeError::Internal(e.to_string()))?;
    Ok(buf)
}

fn mlkem_decaps(seed: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-KEM-768 seed".into()))?;
    let mut decap = OsslAsymcipher::new(&c, EncOp::Decapsulate, &mut key, None)
        .map_err(|_| SmimeError::DecryptionFailed)?;
    let shared = decap
        .decapsulate(ciphertext)
        .map_err(|_| SmimeError::DecryptionFailed)?;
    let bytes: &[u8] = shared.as_ref();
    bytes.try_into().map_err(|_| SmimeError::DecryptionFailed)
}

fn mlkem_encaps(ek: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(ek.to_vec()),
            prikey: None,
            seed: None,
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-KEM ek".into()))?;
    let mut enc = OsslAsymcipher::new(&c, EncOp::Encapsulate, &mut key, None)
        .map_err(|_| SmimeError::Internal("encapsulate".into()))?;
    let mut ct = vec![0u8; MLKEM_CT_LEN];
    let (ss, n) = enc
        .encapsulate(&mut ct)
        .map_err(|_| SmimeError::Internal("encapsulate".into()))?;
    ct.truncate(n);
    let shared: [u8; 32] = ss
        .as_slice()
        .try_into()
        .map_err(|_| SmimeError::Internal("ml-kem shared".into()))?;
    Ok((ct, shared))
}

fn mldsa_public(seed: &[u8]) -> Result<Vec<u8>> {
    let c = ctx();
    let key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-DSA seed".into()))?;
    match key.export().map_err(|e| SmimeError::Internal(e.to_string()))? {
        PkeyData::Mlkey(MlkeyData { pubkey: Some(ref pk), .. }) => Ok(pk.clone()),
        _ => Err(SmimeError::InvalidKey("ML-DSA public".into())),
    }
}

pub fn hybrid_encrypt_entry() -> Result<KeyEntry> {
    let kem_seed = random(MLKEM_SEED_LEN)?;
    let x_seed = random(32)?;
    let c = ctx();
    let kem = EvpPkey::import(
        &c,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(&kem_seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-KEM-768 seed".into()))?;
    let ek = match kem.export().map_err(|e| SmimeError::Internal(e.to_string()))? {
        PkeyData::Mlkey(MlkeyData { pubkey: Some(ref pk), .. }) => pk.clone(),
        _ => return Err(SmimeError::InvalidKey("ML-KEM ek".into())),
    };
    let x_public = x25519_public(&x_seed)?;
    let mut spki = ek;
    spki.extend_from_slice(&x_public);
    let mut secret = kem_seed;
    secret.extend_from_slice(&x_seed);
    Ok(KeyEntry {
        alg: ALG_MLKEM_HYBRID.to_string(),
        purpose: "encryption".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(&spki),
        pkcs8_b64: Some(b64_encode(&secret)),
    })
}

pub fn mldsa_sign_entry() -> Result<KeyEntry> {
    let seed = random(32)?;
    let public = mldsa_public(&seed)?;
    Ok(KeyEntry {
        alg: ALG_MLDSA65.to_string(),
        purpose: "signing".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(&public),
        pkcs8_b64: Some(b64_encode(&seed)),
    })
}

pub fn encapsulate_hybrid(recipient: &KeyEntry) -> Result<(Vec<u8>, [u8; 32])> {
    let spki = b64_decode(&recipient.spki_b64)?;
    if spki.len() < MLKEM_EK_LEN + 32 {
        return Err(SmimeError::InvalidKey("hybrid SPKI".into()));
    }
    let x_raw = x25519_raw_from_spki_or_raw(&spki[MLKEM_EK_LEN..])?;
    let (ct, ss) = mlkem_encaps(&spki[..MLKEM_EK_LEN])?;
    let eph = random(32)?;
    let eph_pub = x25519_public(&eph)?;
    let shared_x = x25519_dh(&eph, &x_raw)?;
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(&ss);
    concat.extend_from_slice(&shared_x);
    let mask = sha256_32(&concat)?;
    let mut payload = ct;
    payload.extend_from_slice(&eph_pub);
    Ok((payload, mask))
}

fn hybrid_secret(entry: &KeyEntry) -> Result<(Vec<u8>, [u8; 32])> {
    let secret = b64_decode(
        entry
            .pkcs8_b64
            .as_ref()
            .ok_or(SmimeError::InvalidKey("hybrid sk".into()))?,
    )?;
    if secret.len() < MLKEM_SEED_LEN + 32 {
        return Err(SmimeError::InvalidKey("hybrid secret".into()));
    }
    let x_seed: [u8; 32] = secret[MLKEM_SEED_LEN..MLKEM_SEED_LEN + 32]
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("x25519 seed".into()))?;
    Ok((secret[..MLKEM_SEED_LEN].to_vec(), x_seed))
}

pub fn decapsulate_and_decrypt(entry: &KeyEntry, cms: &[u8]) -> Result<Vec<u8>> {
    let (kem_seed, x_seed) = hybrid_secret(entry)?;
    let (recip, iv, ct) = extract_ori_iv_ct(cms)?;
    let payload = extract_ori_payload(&recip)?;
    if payload.len() < MLKEM_CT_LEN + 32 + 32 {
        return Err(SmimeError::MalformedMessage);
    }
    let eph: [u8; 32] = payload[MLKEM_CT_LEN..MLKEM_CT_LEN + 32]
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let wrapped: [u8; 32] = payload[MLKEM_CT_LEN + 32..MLKEM_CT_LEN + 64]
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let ss = mlkem_decaps(&kem_seed, &payload[..MLKEM_CT_LEN])?;
    let shared_x = x25519_dh(&x_seed, &eph)?;
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(&ss);
    concat.extend_from_slice(&shared_x);
    let mask = sha256_32(&concat)?;
    let mut cek = wrapped;
    for (w, s) in cek.iter_mut().zip(mask.iter()) {
        *w ^= s;
    }
    aes_decrypt_pub(&cek, &iv, &ct)
}

pub fn pop_hybrid(
    entry: &KeyEntry,
    kem_ciphertext: &[u8],
    ephemeral_x25519: &[u8],
) -> Result<Vec<u8>> {
    if kem_ciphertext.len() != MLKEM_CT_LEN {
        return Err(SmimeError::InvalidArgument("ML-KEM-768 ct".into()));
    }
    let (kem_seed, x_seed) = hybrid_secret(entry)?;
    let ss = mlkem_decaps(&kem_seed, kem_ciphertext)?;
    let eph = x25519_raw_from_spki_or_raw(ephemeral_x25519)?;
    let shared_x = x25519_dh(&x_seed, &eph)?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&ss);
    out.extend_from_slice(&shared_x);
    Ok(out)
}

pub fn sign_mldsa(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let seed = b64_decode(entry.pkcs8_b64.as_ref().ok_or(SmimeError::NoSuitableSigningKey)?)?;
    if seed.len() != 32 {
        return Err(SmimeError::InvalidKey("ML-DSA seed".into()));
    }
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(&seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-DSA seed".into()))?;
    let mut signer = OsslSignature::new(&c, SigOp::Sign, SigAlg::Mldsa65, &mut key, None)
        .map_err(|e| SmimeError::Internal(e.to_string()))?;
    let mut signature = vec![0u8; 3309];
    signer
        .sign(data, Some(&mut signature))
        .map_err(|e| SmimeError::Internal(e.to_string()))?;
    Ok(signature)
}

pub fn verify_mldsa(data: &[u8], sig: &[u8], entry: &KeyEntry) -> bool {
    if sig.len() != 3309 {
        return false;
    }
    let Ok(vk) = b64_decode(&entry.spki_b64) else {
        return false;
    };
    if vk.len() != 1952 {
        return false;
    }
    let c = ctx();
    let Ok(mut key) = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(vk),
            prikey: None,
            seed: None,
        }),
    ) else {
        return false;
    };
    let Ok(mut verifier) = OsslSignature::new(&c, SigOp::Verify, SigAlg::Mldsa65, &mut key, None)
    else {
        return false;
    };
    verifier.verify(data, Some(sig)).is_ok()
}
