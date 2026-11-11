//! The writers never produce a message the reader refuses: a plaintext of
//! exactly MAX_PLAINTEXT_LEN encrypts and decrypts again, one byte more is
//! refused before encryption, and the reader accepts DER up to
//! MAX_MESSAGE_LEN.

use std::fs;
use std::path::PathBuf;

use scomm_smime_cms::{CmsSmime, MAX_MESSAGE_LEN, MAX_PLAINTEXT_LEN};
use scomm_smime_core::*;

fn file(name: &str) -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scomm");
    fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn limits_cover_every_provider_cap() {
    // Graph's 150 MB message is the largest cap; its DER is about 3/4 of that.
    assert!(MAX_MESSAGE_LEN >= 150_000_000 / 4 * 3);
    assert!(MAX_PLAINTEXT_LEN < MAX_MESSAGE_LEN);
}

#[test]
fn the_largest_plaintext_the_writer_accepts_reads_back() {
    let engine = CmsSmime::new();
    let public = file("classical.pub.json");
    let plaintext = vec![b'A'; MAX_PLAINTEXT_LEN];
    let cms = engine
        .encrypt(&plaintext, &[&public], &EncryptOptions { armored: false })
        .unwrap();
    assert!(cms.len() <= MAX_MESSAGE_LEN, "{} bytes", cms.len());
    let out = engine
        .decrypt(&cms, &file("classical.sec.json"), None)
        .unwrap();
    assert!(out.plaintext == plaintext);
}

#[test]
fn one_byte_more_is_refused_before_encryption() {
    let plaintext = vec![b'A'; MAX_PLAINTEXT_LEN + 1];
    let err = CmsSmime::new()
        .encrypt(
            &plaintext,
            &[&file("classical.pub.json")],
            &EncryptOptions { armored: false },
        )
        .unwrap_err();
    assert!(
        matches!(&err, SmimeError::InvalidArgument(m) if m.contains("MiB")),
        "{err:?}"
    );
}

#[test]
fn the_reader_parses_der_up_to_the_limit() {
    // Not a message, but within the limit: refused as malformed, not as
    // too large.
    let junk = vec![0u8; MAX_MESSAGE_LEN];
    assert!(matches!(
        CmsSmime::new().inspect_message(&junk),
        Err(SmimeError::MalformedMessage)
    ));
}
