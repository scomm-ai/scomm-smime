use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use scomm_smime_core::*;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::bundle::{b64_decode, b64_encode, KeyEntry};
use crate::cert::x25519_raw_from_spki_or_raw;
use crate::cms_envelop::{aes_decrypt_pub, extract_ori_iv_ct, extract_ori_payload};

const MLKEM_CT_LEN: usize = 1088;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_SEED_LEN: usize = 64;

fn kem_seed_from_bytes(bytes: &[u8]) -> Result<ml_kem::Seed> {
    let arr: [u8; MLKEM_SEED_LEN] = bytes
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("ML-KEM seed".into()))?;
    Ok(arr.into())
}

pub fn hybrid_encrypt_entry() -> Result<KeyEntry> {
    let mut kem_seed = [0u8; MLKEM_SEED_LEN];
    OsRng.fill_bytes(&mut kem_seed);
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed.into());
    let ek = dk.encapsulation_key();
    let ek_bytes = ek.to_bytes();
    let x_secret = StaticSecret::random_from_rng(OsRng);
    let x_public = X25519Public::from(&x_secret);
    let mut spki = Vec::new();
    spki.extend_from_slice(ek_bytes.as_slice());
    spki.extend_from_slice(x_public.as_bytes());
    let mut secret = Vec::from(kem_seed);
    secret.extend_from_slice(x_secret.as_bytes());
    Ok(KeyEntry {
        alg: ALG_MLKEM_HYBRID.to_string(),
        purpose: "encryption".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(&spki),
        pkcs8_b64: Some(b64_encode(&secret)),
    })
}

pub fn mldsa_sign_entry() -> Result<KeyEntry> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed((&seed).into());
    let vk = sk.verifying_key();
    Ok(KeyEntry {
        alg: ALG_MLDSA65.to_string(),
        purpose: "signing".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(vk.encode().as_slice()),
        pkcs8_b64: Some(b64_encode(&seed)),
    })
}

pub fn encapsulate_hybrid(recipient: &KeyEntry) -> Result<(Vec<u8>, [u8; 32])> {
    let spki = b64_decode(&recipient.spki_b64)?;
    if spki.len() < MLKEM_EK_LEN + 32 {
        return Err(SmimeError::InvalidKey("hybrid SPKI".into()));
    }
    let ek_bytes: [u8; MLKEM_EK_LEN] = spki[..MLKEM_EK_LEN]
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("ML-KEM ek".into()))?;
    let x_raw = x25519_raw_from_spki_or_raw(&spki[MLKEM_EK_LEN..])?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes.into())
        .map_err(|_| SmimeError::InvalidKey("ML-KEM ek decode".into()))?;
    let (ct, ss) = ek.encapsulate();
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = X25519Public::from(&eph);
    let shared_x = eph.diffie_hellman(&X25519Public::from(x_raw));
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(ss.as_ref());
    concat.extend_from_slice(shared_x.as_bytes());
    let mask: [u8; 32] = Sha256::digest(&concat).into();
    let mut payload = Vec::new();
    payload.extend_from_slice(ct.as_ref());
    payload.extend_from_slice(eph_pub.as_bytes());
    Ok((payload, mask))
}

fn hybrid_secret(entry: &KeyEntry) -> Result<(DecapsulationKey<MlKem768>, [u8; 32])> {
    let secret = b64_decode(
        entry
            .pkcs8_b64
            .as_ref()
            .ok_or(SmimeError::InvalidKey("hybrid sk".into()))?,
    )?;
    if secret.len() < MLKEM_SEED_LEN + 32 {
        return Err(SmimeError::InvalidKey("hybrid secret".into()));
    }
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed_from_bytes(&secret[..MLKEM_SEED_LEN])?);
    let x_seed: [u8; 32] = secret[MLKEM_SEED_LEN..MLKEM_SEED_LEN + 32]
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("x25519 seed".into()))?;
    Ok((dk, x_seed))
}

pub fn decapsulate_and_decrypt(entry: &KeyEntry, cms: &[u8]) -> Result<Vec<u8>> {
    let (dk, x_seed) = hybrid_secret(entry)?;
    let (recip, iv, ct) = extract_ori_iv_ct(cms)?;
    let payload = extract_ori_payload(&recip)?;
    if payload.len() < MLKEM_CT_LEN + 32 + 32 {
        return Err(SmimeError::MalformedMessage);
    }
    let kem_ct: [u8; MLKEM_CT_LEN] = payload[..MLKEM_CT_LEN]
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let eph: [u8; 32] = payload[MLKEM_CT_LEN..MLKEM_CT_LEN + 32]
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let wrapped: [u8; 32] = payload[MLKEM_CT_LEN + 32..MLKEM_CT_LEN + 64]
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let ss = dk.decapsulate((&kem_ct).into());
    let shared_x = StaticSecret::from(x_seed).diffie_hellman(&X25519Public::from(eph));
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(ss.as_ref());
    concat.extend_from_slice(shared_x.as_bytes());
    let mask: [u8; 32] = Sha256::digest(&concat).into();
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
    let (dk, x_seed) = hybrid_secret(entry)?;
    let ct: [u8; MLKEM_CT_LEN] = kem_ciphertext
        .try_into()
        .map_err(|_| SmimeError::InvalidArgument("kem ct".into()))?;
    let ss = dk.decapsulate((&ct).into());
    let eph = x25519_raw_from_spki_or_raw(ephemeral_x25519)?;
    let shared_x = StaticSecret::from(x_seed).diffie_hellman(&X25519Public::from(eph));
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(ss.as_ref());
    out.extend_from_slice(shared_x.as_bytes());
    Ok(out)
}

pub fn sign_mldsa(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let seed = b64_decode(entry.pkcs8_b64.as_ref().ok_or(SmimeError::NoSuitableSigningKey)?)?;
    let seed32: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("ML-DSA seed".into()))?;
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed((&seed32).into());
    Ok(sk.sign(data).encode().as_slice().to_vec())
}

pub fn verify_mldsa(data: &[u8], sig: &[u8], entry: &KeyEntry) -> bool {
    let Ok(vk_bytes) = b64_decode(&entry.spki_b64) else {
        return false;
    };
    let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes.as_slice()) else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&enc_vk);
    let Ok(enc_sig) = EncodedSignature::<MlDsa65>::try_from(sig) else {
        return false;
    };
    let Some(sig) = ml_dsa::Signature::<MlDsa65>::decode(&enc_sig) else {
        return false;
    };
    vk.verify(data, &sig).is_ok()
}
