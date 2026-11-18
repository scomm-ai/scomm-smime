//! ABI 5: certificate lifetime chosen at generation.

use scomm_smime_cms::{cert_info, CmsSmime};
use scomm_smime_core::*;
use serde_json::Value;

const YEAR: i64 = 31_556_952;

fn gen(profile: KeyProfile, validity_years: Option<u32>) -> Result<GeneratedKey> {
    CmsSmime::new().generate_key(&GenerateKeyOptions {
        userid: "Alice <alice@example.com>".into(),
        profile,
        validity_years,
        ..Default::default()
    })
}

/// (notBefore, notAfter) of every certificate in the public bundle.
fn windows(key: &GeneratedKey) -> Vec<(i64, i64)> {
    let bundle: Value = serde_json::from_slice(&key.public).unwrap();
    bundle["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["cert_pem"].as_str().filter(|p| !p.is_empty()))
        .map(|pem| {
            let info = cert_info(pem.as_bytes()).unwrap();
            (info.not_before, info.not_after)
        })
        .collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn every_certificate_runs_the_requested_years_from_now() {
    for (profile, certs) in [
        (KeyProfile::Classical, 1),
        (KeyProfile::PqcCms, 2),
        (KeyProfile::PqcSigning, 1),
    ] {
        for years in [1u32, 3, 10] {
            let w = windows(&gen(profile, Some(years)).unwrap());
            assert_eq!(w.len(), certs, "{profile:?}");
            let now = now();
            for (not_before, not_after) in w {
                assert!((now - 86_400 - not_before).abs() < 120, "{profile:?} notBefore");
                assert!((now + i64::from(years) * YEAR - not_after).abs() < 120, "{profile:?}");
            }
        }
    }
}

#[test]
fn no_validity_keeps_the_fixed_window() {
    for (not_before, not_after) in windows(&gen(KeyProfile::PqcCms, None).unwrap()) {
        assert_eq!(not_before, 1_704_067_200); // 2024-01-01
        assert_eq!(not_after, 2_019_686_400); // 2034-01-01
    }
}

#[test]
fn out_of_range_validity_is_refused() {
    for years in [0, MAX_VALIDITY_YEARS + 1] {
        assert!(matches!(
            gen(KeyProfile::Classical, Some(years)),
            Err(SmimeError::InvalidArgument(_))
        ));
    }
}
