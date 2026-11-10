// ABI 3 result types (task 3.6), parsed from the JSON the native side
// writes (`crates/scomm-smime-ffi/src/lib.rs`).

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:scomm_smime/scomm_smime.dart';

void main() {
  test('verdict keeps validity apart from trust', () {
    final v = SmimeSignatureVerdict.fromJson({
      'validity': 'valid',
      'format': 's1',
      'signer_fingerprint': 'ab' * 32,
      'signer_cert_pem': '-----BEGIN CERTIFICATE-----\n...',
      'chain': 'untrusted-root',
      'email_match': true,
      'weak_algorithm': false,
      'revocation': 'not-checked',
    });
    expect(v.isValid, isTrue);
    expect(v.chain, SmimeChain.untrustedRoot);
    expect(v.emailMatch, isTrue);
    expect(v.isLegacy, isFalse);
    expect(v.signerFingerprint, 'ab' * 32);
    expect(v.revocationChecked, isFalse);
  });

  test('every native validity and chain name maps', () {
    const validity = {
      'valid': SmimeValidity.valid,
      'invalid': SmimeValidity.invalid,
      'unknown-signer': SmimeValidity.unknownSigner,
      'malformed': SmimeValidity.malformed,
      'unsupported': SmimeValidity.unsupported,
    };
    const chain = {
      'trusted-root': SmimeChain.trustedRoot,
      'untrusted-root': SmimeChain.untrustedRoot,
      'no-chain': SmimeChain.noChain,
      'expired': SmimeChain.expired,
      'not-yet-valid': SmimeChain.notYetValid,
      'wrong-purpose': SmimeChain.wrongPurpose,
    };
    for (final e in validity.entries) {
      expect(SmimeSignatureVerdict.fromJson({'validity': e.key}).validity,
          e.value);
    }
    for (final e in chain.entries) {
      expect(SmimeCertCheck.fromJson({'chain': e.key}).chain, e.value);
    }
  });

  test('a malformed or unknown verdict is never valid', () {
    final v = SmimeSignatureVerdict.fromJson({
      'validity': 'malformed',
      'format': null,
      'chain': 'no-chain',
      'email_match': null,
      'weak_algorithm': false,
    });
    expect(v.isValid, isFalse);
    expect(v.format, isNull);
    expect(v.emailMatch, isNull);
    expect(
        SmimeSignatureVerdict.fromJson({'validity': 'something new'}).isValid,
        isFalse);
  });

  test('legacy S0 verdict', () {
    final v = SmimeSignatureVerdict.fromJson({
      'validity': 'valid',
      'format': 's0',
      'signer_fingerprint': 'cd' * 32,
      'chain': 'no-chain',
      'weak_algorithm': false,
    });
    expect(v.isLegacy, isTrue);
    expect(v.signerCertPem, isNull);
  });

  test('certificate info keeps the former X509CertInfo fields', () {
    final i = SmimeCertificateInfo.fromJson({
      'version': 3,
      'serial_hex': 'A1B2C',
      'subject_dn': 'C=DE, O=Example GmbH, CN=Carol Example',
      'issuer_dn': 'CN=Test Root',
      'not_before': 1704067200,
      'not_after': 2019686400,
      'public_key_algorithm': 'rsaEncryption',
      'key_bits': 2048,
      'sha1_hex': 'AA' * 20,
      'sha256_hex': 'BB' * 32,
      'spki_sha256_hex': 'cc' * 32,
      'is_self_signed': false,
      'key_usages': ['Digital Signature', 'Key Encipherment'],
      'extended_key_usages': ['E-mail Protection'],
      'subject_key_identifier': null,
      'email_address': 'carol@example.com',
      'common_name': 'Carol Example',
    });
    expect(i.notBefore, DateTime.utc(2024));
    expect(i.notAfter, DateTime.utc(2034));
    expect(i.keyUsages, ['Digital Signature', 'Key Encipherment']);
    expect(i.subjectKeyIdentifier, isNull);
    expect(i.emailAddress, 'carol@example.com');
    expect(i.spkiSha256Hex, 'cc' * 32);
  });

  test('key info carries legacy key IDs', () {
    final c = SmimeCertInspect.fromJson({
      'fingerprint': 'NEW',
      'usage': 'signing',
      'legacy_key_ids': ['OLD'],
    });
    expect(c.legacyKeyIds, ['OLD']);
    expect(
        SmimeCertInspect.fromJson({'fingerprint': 'X'}).legacyKeyIds, isEmpty);
  });

  test('decrypt result names integrity protection by format', () {
    SmimeDecryptResult r(String f) =>
        SmimeDecryptResult(plaintext: Uint8List(0), format: f, algorithm: 'x');
    expect(r('f1').integrityProtected, isTrue);
    expect(r('f0-std').integrityProtected, isFalse);
    expect(r('f0-scomm').integrityProtected, isFalse);
  });

  test('certificate purposes match the C ABI', () {
    expect(SmimeCertPurpose.signing.wire, 0);
    expect(SmimeCertPurpose.encryption.wire, 1);
  });
}
