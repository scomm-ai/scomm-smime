import 'dart:typed_data';

class ScommSmimeException implements Exception {
  ScommSmimeException(this.code, this.message);

  final int code;
  final String message;

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
  });

  final String fingerprint;
  final String serial;
  final String algorithm;
  final String usage;
  final bool hasSecret;
  final bool pqc;
  final String? email;
  final String subject;

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
  pqcCms(1);

  const SmimeKeyProfile(this.wire);
  final int wire;
}

class SmimeMessageInspect {
  const SmimeMessageInspect({
    required this.encrypted,
    required this.signed,
    required this.pqc,
    required this.algorithm,
  });

  final bool encrypted;
  final bool signed;
  final bool pqc;
  final String algorithm;

  factory SmimeMessageInspect.fromJson(Map<String, dynamic> json) {
    return SmimeMessageInspect(
      encrypted: json['encrypted'] as bool? ?? false,
      signed: json['signed'] as bool? ?? false,
      pqc: json['pqc'] as bool? ?? false,
      algorithm: json['algorithm'] as String? ?? '',
    );
  }
}

class CompositePopSignatures {
  const CompositePopSignatures({required this.mldsa, required this.ed25519});

  final Uint8List mldsa;
  final Uint8List ed25519;
}
