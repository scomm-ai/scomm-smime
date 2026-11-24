import 'dart:typed_data';

class ScommSmimeException implements Exception {
  ScommSmimeException(this.code, this.message, {this.evidence});

  final int code;
  final String message;

  /// Optional sanitized evidence from the failed native operation.
  final Map<String, Object?>? evidence;

  @override
  String toString() => 'ScommSmimeException($code): $message';
}

class SmimeCertInspect {
  const SmimeCertInspect({
    required this.fingerprint,
    required this.serial,
    required this.algorithm,
    required this.usage,
    required this.hasSecret,
    required this.pqc,
    this.email,
    this.subject = '',
    this.legacyKeyIds = const [],
  });

  final String fingerprint;
  final String serial;
  final String algorithm;
  final String usage;
  final bool hasSecret;
  final bool pqc;
  final String? email;
  final String subject;

  /// Earlier IDs of this key (an ML-DSA key before it gained a
  /// certificate); references to them still mean this key.
  final List<String> legacyKeyIds;

  bool get isSigning => usage == 'signing';
  bool get isEncryption => usage == 'encryption';

  factory SmimeCertInspect.fromJson(Map<String, dynamic> json) {
    return SmimeCertInspect(
      fingerprint: json['fingerprint'] as String? ?? '',
      serial: json['serial'] as String? ?? '',
      algorithm: json['algorithm'] as String? ?? '',
      usage: json['usage'] as String? ?? 'encryption',
      hasSecret: json['has_secret'] as bool? ?? false,
      pqc: json['pqc'] as bool? ?? false,
      email: json['email'] as String?,
      subject: json['subject'] as String? ?? '',
      legacyKeyIds: [
        for (final id in json['legacy_key_ids'] as List? ?? const [])
          if (id is String) id,
      ],
    );
  }
}

class SmimeKeyInspect {
  const SmimeKeyInspect({
    required this.algorithm,
    required this.isPqc,
    required this.isPqcSigning,
    required this.identities,
  });

  final String algorithm;
  final bool isPqc;
  final bool isPqcSigning;
  final List<SmimeCertInspect> identities;

  factory SmimeKeyInspect.fromJson(Map<String, dynamic> json) {
    return SmimeKeyInspect(
      algorithm: json['algorithm'] as String? ?? '',
      isPqc: json['is_pqc'] as bool? ?? false,
      isPqcSigning: json['is_pqc_signing'] as bool? ?? false,
      identities: [
        for (final raw in json['identities'] as List? ?? const [])
          if (raw is Map)
            SmimeCertInspect.fromJson(Map<String, dynamic>.from(raw)),
      ],
    );
  }
}

class GeneratedSmimeKey {
  const GeneratedSmimeKey({
    required this.public,
    required this.secret,
    required this.info,
  });

  final List<int> public;
  final List<int> secret;
  final SmimeKeyInspect info;
}

/// Matches C ABI `profile` on `scomm_smime_generate`.
enum SmimeKeyProfile {
  classical(0),
  pqcCms(1),

  /// ABI 4: only the `smime-mlkem768-x25519` encryption entry.
  pqcEncryption(2),

  /// ABI 4: only the `pqc-mldsa65` signing entry, with its certificate.
  pqcSigning(3);

  const SmimeKeyProfile(this.wire);
  final int wire;
}

class SmimeMessageInspect {
  const SmimeMessageInspect({
    required this.encrypted,
    required this.signed,
    required this.pqc,
    required this.classicalRecipient,
    required this.algorithm,
  });

  final bool encrypted;
  final bool signed;
  final bool pqc;

  /// The content key is also wrapped to a classical recipient.
  final bool classicalRecipient;
  final String algorithm;

  factory SmimeMessageInspect.fromJson(Map<String, dynamic> json) {
    return SmimeMessageInspect(
      encrypted: json['encrypted'] as bool? ?? false,
      signed: json['signed'] as bool? ?? false,
      pqc: json['pqc'] as bool? ?? false,
      classicalRecipient: json['classical_recipient'] as bool? ?? false,
      algorithm: json['algorithm'] as String? ?? '',
    );
  }
}

/// Signature math, apart from trust (ABI 3, `scomm_smime_verify_detached`).
enum SmimeValidity { valid, invalid, unknownSigner, malformed, unsupported }

/// Path B result for the signer certificate.
enum SmimeChain {
  trustedRoot,
  untrustedRoot,
  noChain,
  expired,
  notYetValid,
  wrongPurpose,
}

SmimeValidity _validity(Object? v) => switch (v) {
      'valid' => SmimeValidity.valid,
      'invalid' => SmimeValidity.invalid,
      'unknown-signer' => SmimeValidity.unknownSigner,
      'unsupported' => SmimeValidity.unsupported,
      _ => SmimeValidity.malformed,
    };

SmimeChain _chain(Object? v) => switch (v) {
      'trusted-root' => SmimeChain.trustedRoot,
      'untrusted-root' => SmimeChain.untrustedRoot,
      'expired' => SmimeChain.expired,
      'not-yet-valid' => SmimeChain.notYetValid,
      'wrong-purpose' => SmimeChain.wrongPurpose,
      _ => SmimeChain.noChain,
    };

/// Per-signature verdict. `verified` is the app's decision from this plus
/// its own pins; validity alone never means trusted.
class SmimeSignatureVerdict {
  const SmimeSignatureVerdict({
    required this.validity,
    required this.chain,
    required this.weakAlgorithm,
    this.format,
    this.signerFingerprint,
    this.signerCertPem,
    this.emailMatch,
  });

  final SmimeValidity validity;

  /// `s1` (SignedData) or `s0` (legacy Scomm); null when not a signature.
  final String? format;

  /// Lowercase hex SHA-256 of the signer's SubjectPublicKeyInfo; the same
  /// for S0 and S1, and the value pins are keyed by.
  final String? signerFingerprint;
  final String? signerCertPem;
  final SmimeChain chain;

  /// Null when no sender was given or there is no certificate.
  final bool? emailMatch;
  final bool weakAlgorithm;

  /// Revocation is never checked: the app contacts no server.
  bool get revocationChecked => false;

  bool get isValid => validity == SmimeValidity.valid;
  bool get isLegacy => format == 's0';

  factory SmimeSignatureVerdict.fromJson(Map<String, dynamic> json) {
    return SmimeSignatureVerdict(
      validity: _validity(json['validity']),
      format: json['format'] as String?,
      signerFingerprint: json['signer_fingerprint'] as String?,
      signerCertPem: json['signer_cert_pem'] as String?,
      chain: _chain(json['chain']),
      emailMatch: json['email_match'] as bool?,
      weakAlgorithm: json['weak_algorithm'] as bool? ?? false,
    );
  }
}

/// `scomm_smime_check_certificate` purposes.
enum SmimeCertPurpose {
  signing(0),
  encryption(1);

  const SmimeCertPurpose(this.wire);
  final int wire;
}

class SmimeCertCheck {
  const SmimeCertCheck({required this.chain, this.emailMatch});

  final SmimeChain chain;
  final bool? emailMatch;

  factory SmimeCertCheck.fromJson(Map<String, dynamic> json) {
    return SmimeCertCheck(
      chain: _chain(json['chain']),
      emailMatch: json['email_match'] as bool?,
    );
  }
}

/// Certificate details read natively (ABI 3, `scomm_smime_cert_info`).
/// Fields and strings match the app's former Dart `X509CertInfo`.
class SmimeCertificateInfo {
  const SmimeCertificateInfo({
    required this.version,
    required this.serialHex,
    required this.subjectDn,
    required this.issuerDn,
    required this.notBefore,
    required this.notAfter,
    required this.publicKeyAlgorithm,
    required this.keyBits,
    required this.sha1Hex,
    required this.sha256Hex,
    required this.spkiSha256Hex,
    required this.isSelfSigned,
    required this.keyUsages,
    required this.extendedKeyUsages,
    this.subjectKeyIdentifier,
    this.emailAddress,
    this.commonName,
  });

  final int version;
  final String serialHex;
  final String subjectDn;
  final String issuerDn;
  final DateTime notBefore;
  final DateTime notAfter;
  final String publicKeyAlgorithm;
  final int keyBits;
  final String sha1Hex;
  final String sha256Hex;

  /// The pin fingerprint, as in [SmimeSignatureVerdict.signerFingerprint].
  final String spkiSha256Hex;
  final bool isSelfSigned;
  final List<String> keyUsages;
  final List<String> extendedKeyUsages;
  final String? subjectKeyIdentifier;
  final String? emailAddress;
  final String? commonName;

  factory SmimeCertificateInfo.fromJson(Map<String, dynamic> json) {
    DateTime time(Object? v) => DateTime.fromMillisecondsSinceEpoch(
          ((v as num?) ?? 0).toInt() * 1000,
          isUtc: true,
        );
    List<String> strings(Object? v) => [
          for (final s in v as List? ?? const [])
            if (s is String) s,
        ];
    return SmimeCertificateInfo(
      version: (json['version'] as num?)?.toInt() ?? 0,
      serialHex: json['serial_hex'] as String? ?? '',
      subjectDn: json['subject_dn'] as String? ?? '',
      issuerDn: json['issuer_dn'] as String? ?? '',
      notBefore: time(json['not_before']),
      notAfter: time(json['not_after']),
      publicKeyAlgorithm: json['public_key_algorithm'] as String? ?? '',
      keyBits: (json['key_bits'] as num?)?.toInt() ?? 0,
      sha1Hex: json['sha1_hex'] as String? ?? '',
      sha256Hex: json['sha256_hex'] as String? ?? '',
      spkiSha256Hex: json['spki_sha256_hex'] as String? ?? '',
      isSelfSigned: json['is_self_signed'] as bool? ?? false,
      keyUsages: strings(json['key_usages']),
      extendedKeyUsages: strings(json['extended_key_usages']),
      subjectKeyIdentifier: json['subject_key_identifier'] as String?,
      emailAddress: json['email_address'] as String?,
      commonName: json['common_name'] as String?,
    );
  }
}

/// Plaintext plus how it was protected (D6): anything other than `f1` is
/// not integrity protected.
class SmimeDecryptResult {
  const SmimeDecryptResult({
    required this.plaintext,
    required this.format,
    required this.algorithm,
  });

  final Uint8List plaintext;
  final String format;
  final String algorithm;

  bool get integrityProtected => format == 'f1';
}

class CompositePopSignatures {
  const CompositePopSignatures({required this.mldsa, required this.ed25519});

  final Uint8List mldsa;
  final Uint8List ed25519;
}

/// [ScommSmime.createCsr] result.
class SmimeCsr {
  const SmimeCsr({
    required this.csrPem,
    required this.pkcs8B64,
    required this.spkiB64,
    required this.spkiSha256,
  });

  /// `-----BEGIN CERTIFICATE REQUEST-----`; holds no private key.
  final String csrPem;

  /// The new private key, unencrypted PKCS#8 DER in Base64.
  final String pkcs8B64;
  final String spkiB64;

  /// SHA-256 of the public key (SubjectPublicKeyInfo), upper-case hex.
  final String spkiSha256;

  factory SmimeCsr.fromJson(Map<String, dynamic> json) => SmimeCsr(
    csrPem: json['csr_pem'] as String,
    pkcs8B64: json['pkcs8_b64'] as String,
    spkiB64: json['spki_b64'] as String,
    spkiSha256: json['spki_sha256'] as String,
  );
}

/// One certificate from [ScommSmime.importFiles].
class SmimeImportedCertificate {
  const SmimeImportedCertificate({
    required this.certPem,
    required this.spkiB64,
    required this.isCa,
    required this.keyAlgorithm,
    this.pkcs8B64,
  });

  final String certPem;
  final String spkiB64;

  /// basicConstraints cA (or keyCertSign). Never trusted because of this.
  final bool isCa;

  /// `rsa`, `ec`, `ed25519`, `ed448`, `dsa` or `other`.
  final String keyAlgorithm;

  /// The matching private key, unencrypted PKCS#8 DER in Base64.
  final String? pkcs8B64;

  bool get hasPrivateKey => pkcs8B64 != null;

  factory SmimeImportedCertificate.fromJson(Map<String, dynamic> json) {
    return SmimeImportedCertificate(
      certPem: json['cert_pem'] as String? ?? '',
      spkiB64: json['spki_b64'] as String? ?? '',
      isCa: json['is_ca'] as bool? ?? false,
      keyAlgorithm: json['key_algorithm'] as String? ?? 'other',
      pkcs8B64: json['pkcs8_b64'] as String?,
    );
  }
}

/// [ScommSmime.importFiles] result: personal certificates first.
class SmimeImportResult {
  const SmimeImportResult({required this.certificates, required this.unmatchedKeys});

  final List<SmimeImportedCertificate> certificates;

  /// Private keys that belong to none of the certificates.
  final int unmatchedKeys;

  factory SmimeImportResult.fromJson(Map<String, dynamic> json) {
    return SmimeImportResult(
      certificates: [
        for (final raw in json['certificates'] as List? ?? const [])
          if (raw is Map)
            SmimeImportedCertificate.fromJson(Map<String, dynamic>.from(raw)),
      ],
      unmatchedKeys: (json['unmatched_keys'] as num?)?.toInt() ?? 0,
    );
  }
}
