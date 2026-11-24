import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:scomm_openpgp/scomm_openpgp.dart';

import 'types.dart';

/// Lowest native ABI with the verdict, detached signing, certificate info,
/// trust roots, ML-DSA migration and decrypt-with-format symbols.
const int scommSmimeAbiTrust = 3;

/// Lowest native ABI with the post-quantum-only key profiles
/// ([SmimeKeyProfile.pqcEncryption], [SmimeKeyProfile.pqcSigning]) and
/// [ScommSmime.removeEntries].
const int scommSmimeAbiPqcOnly = 4;

/// Lowest native ABI with [ScommSmime.importFiles].
const int scommSmimeAbiImport = 6;

/// Lowest native ABI with [ScommSmime.createCsr].
const int scommSmimeAbiCsr = 7;

/// RSA sizes [ScommSmime.createCsr] accepts.
const List<int> scommSmimeCsrKeyBits = [2048, 3072];

/// [ScommSmimeException.code] for an import file that needs a password.
const int scommSmimePasswordRequired = 12;

/// [ScommSmimeException.code] for a password that did not open the file.
const int scommSmimeWrongPassword = 13;

typedef _DetailsDecryptN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DetailsDecryptD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DetailsVerifyN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DetailsVerifyD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);

typedef _DetailsInspectN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Uint32,
  ffi.Uint32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DetailsInspectD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);

typedef _AbiVersionN = ffi.Uint32 Function();
typedef _VerifyDetachedN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _VerifyDetachedD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SetRootsN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Size>,
);
typedef _SetRootsD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Size>,
);
typedef _CheckCertN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _CheckCertD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _TwoInN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _TwoInD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DecryptExN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DecryptExD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _AbiVersionD = int Function();
typedef _BufferFreeN = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size);
typedef _BufferFreeD = void Function(ffi.Pointer<ffi.Uint8>, int);
typedef _LastErrorN = ffi.Int32 Function(
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _LastErrorD = int Function(
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _InspectN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _InspectD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _GenerateN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _GenerateD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _GenerateValidityN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Uint32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _GenerateValidityD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _ReadyN = ffi.Int32 Function();
typedef _ReadyD = int Function();
typedef _EncryptN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _EncryptD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DecryptN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DecryptD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SignN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SignD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SignAlgN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SignAlgD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _VerifyN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Int32>,
);
typedef _VerifyD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Int32>,
);
typedef _TestPassN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
);
typedef _TestPassD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _PopHybridN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _PopHybridD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);

/// Bytes-in / bytes-out S/MIME. The CMS engine does not appear in this API.
class ScommSmime {
  ScommSmime._(this._lib)
      : _abiVersion = _lib.lookupFunction<_AbiVersionN, _AbiVersionD>(
          'scomm_smime_abi_version',
        ),
        _bufferFree = _lib.lookupFunction<_BufferFreeN, _BufferFreeD>(
          'scomm_smime_buffer_free',
        ),
        _lastError = _lib.lookupFunction<_LastErrorN, _LastErrorD>(
          'scomm_smime_last_error',
        ),
        _inspect = _lib.lookupFunction<_InspectN, _InspectD>(
          'scomm_smime_inspect',
        ),
        _generate = _lib.lookupFunction<_GenerateN, _GenerateD>(
          'scomm_smime_generate',
        ),
        _pqcReady = _lib.lookupFunction<_ReadyN, _ReadyD>(
          'scomm_smime_pqc_ready',
        ),
        _exportPublic = _lib.lookupFunction<_InspectN, _InspectD>(
          'scomm_smime_export_public',
        ),
        _encrypt = _lib.lookupFunction<_EncryptN, _EncryptD>(
          'scomm_smime_encrypt',
        ),
        _decrypt = _lib.lookupFunction<_DecryptN, _DecryptD>(
          'scomm_smime_decrypt',
        ),
        _sign = _lib.lookupFunction<_SignAlgN, _SignAlgD>('scomm_smime_sign'),
        _verify = _lib.lookupFunction<_VerifyN, _VerifyD>('scomm_smime_verify'),
        _inspectMessage = _lib.lookupFunction<_InspectN, _InspectD>(
          'scomm_smime_inspect_message',
        ),
        _testPass = _lib.lookupFunction<_TestPassN, _TestPassD>(
          'scomm_smime_test_passphrase',
        ),
        _popSign = _lib.lookupFunction<_SignN, _SignD>(
          'scomm_smime_pop_sign_mldsa',
        ),
        _popHybrid = _lib.lookupFunction<_PopHybridN, _PopHybridD>(
          'scomm_smime_pop_hybrid_shared',
        ),
        _popSignClassical = _lib.lookupFunction<_SignN, _SignD>(
          'scomm_smime_pop_sign_classical',
        ),
        _popRsaDecrypt = _lib.lookupFunction<_SignN, _SignD>(
          'scomm_smime_pop_rsa_decrypt',
        );

  static ScommSmime? _instance;

  static ScommSmime get instance => _instance ??= ScommSmime._(_open());

  final ffi.DynamicLibrary _lib;
  final int Function() _abiVersion;
  final void Function(ffi.Pointer<ffi.Uint8>, int) _bufferFree;
  final _LastErrorD _lastError;
  final _InspectD _inspect;
  final _GenerateD _generate;
  final int Function() _pqcReady;
  final _InspectD _exportPublic;
  final _EncryptD _encrypt;
  final _DecryptD _decrypt;
  final _SignAlgD _sign;
  final _VerifyD _verify;
  final _InspectD _inspectMessage;
  final _TestPassD _testPass;
  final _SignD _popSign;
  final _PopHybridD _popHybrid;
  final _SignD _popSignClassical;
  final _SignD _popRsaDecrypt;

  int get abiVersion => _abiVersion();

  // ABI 3 symbols are looked up on first use, so the older calls keep
  // working against an ABI 2 library until the native rev is bumped.
  late final _VerifyDetachedD _verifyDetached =
      _lib.lookupFunction<_VerifyDetachedN, _VerifyDetachedD>(
    'scomm_smime_verify_detached',
  );
  late final _SignAlgD _signDetached =
      _lib.lookupFunction<_SignAlgN, _SignAlgD>('scomm_smime_sign_detached');
  late final _InspectD _certInfo = _lib.lookupFunction<_InspectN, _InspectD>(
    'scomm_smime_cert_info',
  );
  late final _SetRootsD _setTrustRoots = _lib
      .lookupFunction<_SetRootsN, _SetRootsD>('scomm_smime_set_trust_roots');
  late final _CheckCertD _checkCertificate =
      _lib.lookupFunction<_CheckCertN, _CheckCertD>(
    'scomm_smime_check_certificate',
  );
  late final _TwoInD _addMldsaCertificates = _lib
      .lookupFunction<_TwoInN, _TwoInD>('scomm_smime_add_mldsa_certificates');
  late final _TwoInD _removeEntries =
      _lib.lookupFunction<_TwoInN, _TwoInD>('scomm_smime_remove_entries');
  late final int Function() _maxPlaintextLen =
      _lib.lookupFunction<ffi.Size Function(), int Function()>(
    'scomm_smime_max_plaintext_len',
  );

  /// Largest plaintext [encrypt] accepts. Check it before sending: anything
  /// larger is refused, and anything within it can be read back.
  int get maxPlaintextBytes {
    _requireAbi(scommSmimeAbiTrust);
    return _maxPlaintextLen();
  }

  late final _DecryptExD _decryptEx =
      _lib.lookupFunction<_DecryptExN, _DecryptExD>('scomm_smime_decrypt_ex');

  void _requireAbi(int version) {
    final have = abiVersion;
    if (have < version) {
      throw StateError(
        'scomm_smime native ABI $have is older than the $version this call needs',
      );
    }
  }

  /// Signature verdict (validity, chain, e-mail match, weak flag). Pass the
  /// bundle already held for the sender as [publicKey] (needed for legacy
  /// S0 signatures) and the From address as [sender].
  SmimeSignatureVerdict verifyDetached({
    required List<int> data,
    required List<int> signature,
    List<int>? publicKey,
    String? sender,
  }) {
    _requireAbi(scommSmimeAbiTrust);
    return using((arena) {
      final d = _copy(arena, data);
      final sig = _copy(arena, signature);
      final pk = _copy(arena, publicKey ?? const []);
      final from = _copy(arena, utf8.encode(sender ?? ''));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _verifyDetached(
        d.ptr,
        d.len,
        sig.ptr,
        sig.len,
        pk.ptr,
        pk.len,
        from.ptr,
        from.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return SmimeSignatureVerdict.fromJson(
        jsonDecode(utf8.decode(_take(outPtr.value, outLen.value)))
            as Map<String, dynamic>,
      );
    });
  }

  /// Detached signature; [algorithm] may also be `smime-rsa-pkcs1-sha256`.
  Uint8List signDetached({
    required List<int> data,
    required List<int> privateKey,
    required String algorithm,
    String passphrase = '',
  }) {
    _requireAbi(scommSmimeAbiTrust);
    return using((arena) {
      final d = _copy(arena, data);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final alg = _copy(arena, utf8.encode(algorithm));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _signDetached(
        d.ptr,
        d.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        alg.ptr,
        alg.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  /// Certificate details (PEM or DER).
  SmimeCertificateInfo certInfo(List<int> certificate) {
    _requireAbi(scommSmimeAbiTrust);
    return SmimeCertificateInfo.fromJson(
      jsonDecode(utf8.decode(_call1(certificate, _certInfo)))
          as Map<String, dynamic>,
    );
  }

  /// Loads the bundled e-mail roots (PEM) once at startup; returns how many
  /// were read. Empty input clears them.
  int setTrustRoots(List<int> pem) {
    _requireAbi(scommSmimeAbiTrust);
    return using((arena) {
      final p = _copy(arena, pem);
      final count = arena<ffi.Size>();
      final code = _setTrustRoots(p.ptr, p.len, count);
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return count.value;
    });
  }

  /// Checks a certificate (with its chain, PEM) against the bundled roots.
  SmimeCertCheck checkCertificate({
    required List<int> certificatePem,
    required SmimeCertPurpose purpose,
    String? email,
  }) {
    _requireAbi(scommSmimeAbiTrust);
    return using((arena) {
      final c = _copy(arena, certificatePem);
      final e = _copy(arena, utf8.encode(email ?? ''));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _checkCertificate(
        c.ptr,
        c.len,
        e.ptr,
        e.len,
        purpose.wire,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return SmimeCertCheck.fromJson(
        jsonDecode(utf8.decode(_take(outPtr.value, outLen.value)))
            as Map<String, dynamic>,
      );
    });
  }

  /// ML-DSA certificate migration: the updated secret bundle, or null when
  /// nothing needed a certificate. Write it back only when non-null.
  Uint8List? addMldsaCertificates({
    required List<int> secretKey,
    required String email,
  }) {
    _requireAbi(scommSmimeAbiTrust);
    return using((arena) {
      final sk = _copy(arena, secretKey);
      final e = _copy(arena, utf8.encode(email));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _addMldsaCertificates(
        sk.ptr,
        sk.len,
        e.ptr,
        e.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      final out = _take(outPtr.value, outLen.value);
      return out.isEmpty ? null : Uint8List.fromList(out);
    });
  }

  /// [secretKey] without the entries whose `spki_b64` is in [spkis]. Other
  /// entries are returned unchanged. Throws rather than leave no entry.
  Uint8List removeEntries({
    required List<int> secretKey,
    required List<String> spkis,
  }) {
    _requireAbi(scommSmimeAbiPqcOnly);
    return using((arena) {
      final sk = _copy(arena, secretKey);
      final ids = _copy(arena, utf8.encode(jsonEncode(spkis)));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _removeEntries(
        sk.ptr,
        sk.len,
        ids.ptr,
        ids.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  late final _InspectD _createCsr =
      _lib.lookupFunction<_InspectN, _InspectD>('scomm_smime_create_csr');

  /// A PKCS#10 request for a CA-issued S/MIME certificate, with a new RSA
  /// key of [keyBits] (see [scommSmimeCsrKeyBits]) generated natively (ABI
  /// 7). [name] puts a person's name in the subject (individual validated);
  /// without it the subject names [email] only (mailbox validated). The
  /// request carries [email] as its subject alternative name, the key usages
  /// for [sign] and [encrypt], and e-mail protection; its signature is
  /// checked before it is returned. The result holds the unencrypted private
  /// key: store it at once, never log it.
  SmimeCsr createCsr({
    required String email,
    String? name,
    required int keyBits,
    required bool sign,
    required bool encrypt,
  }) {
    _requireAbi(scommSmimeAbiCsr);
    return using((arena) {
      final req = _copy(
        arena,
        utf8.encode(
          jsonEncode({
            'email': email,
            if (name != null) 'name': name,
            'key_bits': keyBits,
            'sign': sign,
            'encrypt': encrypt,
          }),
        ),
      );
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _createCsr(req.ptr, req.len, outPtr, outLen);
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return SmimeCsr.fromJson(
        jsonDecode(utf8.decode(_take(outPtr.value, outLen.value)))
            as Map<String, dynamic>,
      );
    });
  }

  late final _TwoInD _import =
      _lib.lookupFunction<_TwoInN, _TwoInD>('scomm_smime_import');

  /// Reads S/MIME import files with OpenSSL (ABI 6): PKCS#12, PKCS#7 (PEM
  /// or DER, also with the whole PEM block on one line), PEM and DER
  /// certificates, PKCS#8 / PKCS#1 / SEC1 keys, encrypted PKCS#8 and
  /// `Proc-Type: 4,ENCRYPTED` keys. Each element of [files] is one file.
  ///
  /// Throws [ScommSmimeException] with [scommSmimePasswordRequired] or
  /// [scommSmimeWrongPassword] for password problems. The result holds
  /// unencrypted private keys: store them at once, never log them.
  SmimeImportResult importFiles({
    required List<List<int>> files,
    String password = '',
  }) {
    _requireAbi(scommSmimeAbiImport);
    return using((arena) {
      final f = _copy(arena, _encodeRecipients(files));
      final pass = _copy(arena, utf8.encode(password));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _import(f.ptr, f.len, pass.ptr, pass.len, outPtr, outLen);
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return SmimeImportResult.fromJson(
        jsonDecode(utf8.decode(_take(outPtr.value, outLen.value)))
            as Map<String, dynamic>,
      );
    });
  }

  /// Decrypts and reports the format (`f1`, `f0-std`, `f0-scomm`).
  SmimeDecryptResult decryptWithFormat({
    required List<int> ciphertext,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    _requireAbi(scommSmimeAbiTrust);
    return using((arena) {
      final ct = _copy(arena, ciphertext);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final jsonPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final jsonLen = arena<ffi.Size>();
      final code = _decryptEx(
        ct.ptr,
        ct.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        outPtr,
        outLen,
        jsonPtr,
        jsonLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      final plaintext = Uint8List.fromList(_take(outPtr.value, outLen.value));
      final meta = jsonDecode(
        utf8.decode(_take(jsonPtr.value, jsonLen.value)),
      ) as Map<String, dynamic>;
      return SmimeDecryptResult(
        plaintext: plaintext,
        format: meta['format'] as String? ?? '',
        algorithm: meta['algorithm'] as String? ?? '',
      );
    });
  }

  bool get pqcReady => _pqcReady() != 0;

  SmimeKeyInspect inspectKey(List<int> key) {
    return SmimeKeyInspect.fromJson(
      jsonDecode(utf8.decode(_call1(key, _inspect))) as Map<String, dynamic>,
    );
  }

  SmimeMessageInspect inspectMessage(List<int> message) {
    return SmimeMessageInspect.fromJson(
      jsonDecode(utf8.decode(_call1(message, _inspectMessage)))
          as Map<String, dynamic>,
    );
  }

  /// ABI 5. Looked up on first use, so older native libraries still
  /// load; passing [generateKey]'s `validityYears` to one throws.
  late final _GenerateValidityD _generateWithValidity = _lib
      .lookupFunction<_GenerateValidityN, _GenerateValidityD>(
    'scomm_smime_generate_with_validity',
  );

  /// [validityYears] (1 to 10) sets how long the key or its certificates
  /// stay valid from now. Null keeps the native default.
  GeneratedSmimeKey generateKey({
    required String userid,
    String passphrase = '',
    int? validityYears,
    SmimeKeyProfile profile = SmimeKeyProfile.classical,
  }) {
    if (profile == SmimeKeyProfile.pqcEncryption ||
        profile == SmimeKeyProfile.pqcSigning) {
      _requireAbi(scommSmimeAbiPqcOnly);
    }
    return using((arena) {
      final user = _copy(arena, utf8.encode(userid));
      final pass = _copy(arena, utf8.encode(passphrase));
      final pubPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final pubLen = arena<ffi.Size>();
      final secPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final secLen = arena<ffi.Size>();
      final jsonPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final jsonLen = arena<ffi.Size>();
      final code = validityYears == null
          ? _generate(
              user.ptr,
              user.len,
              pass.ptr,
              pass.len,
              profile.wire,
              pubPtr,
              pubLen,
              secPtr,
              secLen,
              jsonPtr,
              jsonLen,
            )
          : _generateWithValidity(
              user.ptr,
              user.len,
              pass.ptr,
              pass.len,
              profile.wire,
              validityYears,
              pubPtr,
              pubLen,
              secPtr,
              secLen,
              jsonPtr,
              jsonLen,
            );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      final public = _take(pubPtr.value, pubLen.value);
      final secret = _take(secPtr.value, secLen.value);
      final infoJson = utf8.decode(_take(jsonPtr.value, jsonLen.value));
      return GeneratedSmimeKey(
        public: public,
        secret: secret,
        info: SmimeKeyInspect.fromJson(
          jsonDecode(infoJson) as Map<String, dynamic>,
        ),
      );
    });
  }

  Uint8List exportPublicKey(List<int> secretOrPublic) {
    return Uint8List.fromList(_call1(secretOrPublic, _exportPublic));
  }

  Uint8List encrypt({
    required List<int> plaintext,
    required List<List<int>> recipientPublicKeys,
    bool armored = true,
  }) {
    return using((arena) {
      final pt = _copy(arena, plaintext);
      final recips = _copy(arena, _encodeRecipients(recipientPublicKeys));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _encrypt(
        pt.ptr,
        pt.len,
        recips.ptr,
        recips.len,
        armored ? 1 : 0,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  Uint8List decrypt({
    required List<int> ciphertext,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    return using((arena) {
      final ct = _copy(arena, ciphertext);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _decrypt(
        ct.ptr,
        ct.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  /// [algorithm] is the catalog name of the bundle's signing key to use, such
  /// as `smime-ed25519` or `pqc-mldsa65`.
  Uint8List sign({
    required List<int> data,
    required List<int> privateKey,
    required String algorithm,
    String passphrase = '',
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final alg = _copy(arena, utf8.encode(algorithm));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _sign(
        d.ptr,
        d.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        alg.ptr,
        alg.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  bool verify({
    required List<int> data,
    required List<int> signature,
    required List<int> publicKey,
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sig = _copy(arena, signature);
      final pk = _copy(arena, publicKey);
      final valid = arena<ffi.Int32>();
      final code = _verify(
        d.ptr,
        d.len,
        sig.ptr,
        sig.len,
        pk.ptr,
        pk.len,
        valid,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return valid.value != 0;
    });
  }

  void testPassphrase({required List<int> privateKey, String passphrase = ''}) {
    using((arena) {
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final code = _testPass(sk.ptr, sk.len, pass.ptr, pass.len);
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
    });
  }

  Uint8List popSignMldsa({
    required List<int> data,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _popSign(
        d.ptr,
        d.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  Uint8List popHybridShared({
    required List<int> privateKey,
    required List<int> kemCiphertext,
    required List<int> ephemeralX25519,
    String passphrase = '',
  }) {
    return using((arena) {
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final kem = _copy(arena, kemCiphertext);
      final eph = _copy(arena, ephemeralX25519);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _popHybrid(
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        kem.ptr,
        kem.len,
        eph.ptr,
        eph.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  /// Raw RSA-PSS-SHA256 signature over [data] — no CMS SignedData wrapping,
  /// unlike [sign]. For a pubkey-server `smime-rsa-pss-sha256` artifact's
  /// proof-of-possession self_signature.
  Uint8List popSignClassical({
    required List<int> data,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _popSignClassical(
        d.ptr,
        d.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  /// Raw RSA-OAEP-SHA256 decrypt of [ciphertext] — no CMS EnvelopedData
  /// parsing, unlike [decrypt]. For solving a pubkey-server
  /// `smime-rsa-oaep-sha256` decrypt proof-of-possession challenge (a small
  /// wrapped nonce, not a full CMS message).
  Uint8List popRsaDecrypt({
    required List<int> ciphertext,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    return using((arena) {
      final ct = _copy(arena, ciphertext);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _popRsaDecrypt(
        ct.ptr,
        ct.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  List<int> _call1(
    List<int> input,
    int Function(
      ffi.Pointer<ffi.Uint8>,
      int,
      ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
      ffi.Pointer<ffi.Size>,
    ) fn,
  ) {
    return using((arena) {
      final buf = _copy(arena, input);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = fn(buf.ptr, buf.len, outPtr, outLen);
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError());
      }
      return _take(outPtr.value, outLen.value);
    });
  }

  String _readLastError() {
    return using((arena) {
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      _lastError(outPtr, outLen);
      return utf8.decode(_take(outPtr.value, outLen.value));
    });
  }

  late final _DetailsDecryptD? _detailsDecrypt =
      _lib.providesSymbol('scomm_smime_decrypt_with_details_v1')
          ? _lib.lookupFunction<_DetailsDecryptN, _DetailsDecryptD>(
              'scomm_smime_decrypt_with_details_v1',
            )
          : null;

  late final _DetailsVerifyD? _detailsVerify =
      _lib.providesSymbol('scomm_smime_verify_detached_with_details_v1')
          ? _lib.lookupFunction<_DetailsVerifyN, _DetailsVerifyD>(
              'scomm_smime_verify_detached_with_details_v1',
            )
          : null;

  late final _DetailsInspectD? _detailsInspect =
      _lib.providesSymbol('scomm_smime_inspect_public_envelope_v1')
          ? _lib.lookupFunction<_DetailsInspectN, _DetailsInspectD>(
              'scomm_smime_inspect_public_envelope_v1',
            )
          : null;

  /// Optional versioned native metadata. A malformed diagnostic cannot
  /// change the independently decoded operation result.
  Map<String, Object?>? _takeSecurityEvidence(
    ffi.Pointer<ffi.Uint8> pointer,
    int length,
  ) {
    if (pointer == ffi.nullptr) return null;
    try {
      if (length <= 0 || length > 16 * 1024) return null;
      final parsed = jsonDecode(utf8.decode(pointer.asTypedList(length)));
      if (parsed is! Map<String, Object?> || parsed['version'] != 1)
        return null;
      return parsed;
    } on FormatException {
      return null;
    } finally {
      _bufferFree(pointer, length);
    }
  }

  /// Inspects a complete small artifact without using a key or decrypting.
  /// A null result means this engine has no compatible metadata support.
  Map<String, Object?>? inspectPublicEnvelope(
    List<int> envelope,
  ) {
    final inspect = _detailsInspect;
    if (inspect == null || envelope.isEmpty || envelope.length > 16 * 1024) {
      return null;
    }
    return using((arena) {
      final input = _copy(arena, envelope);
      final out = arena<ffi.Pointer<ffi.Uint8>>();
      final length = arena<ffi.Size>();
      final status = inspect(
        input.ptr,
        input.len,
        1,
        1,
        out,
        length,
      );
      final details = _takeSecurityEvidence(out.value, length.value);
      return status == 0 ? details : null;
    });
  }

  ({SmimeSignatureVerdict verdict, Map<String, Object?>? evidence})
      verifyWithDetails({
    required List<int> data,
    required List<int> signature,
    List<int>? publicKey,
    String? sender,
  }) {
    final verify = _detailsVerify;
    if (verify == null) {
      return (
        verdict: verifyDetached(
          data: data,
          signature: signature,
          publicKey: publicKey,
          sender: sender,
        ),
        evidence: null,
      );
    }
    return using((arena) {
      final body = _copy(arena, data);
      final sig = _copy(arena, signature);
      final key = _copy(arena, publicKey ?? const []);
      final address = _copy(arena, utf8.encode(sender ?? ""));
      final verdict = arena<ffi.Pointer<ffi.Uint8>>();
      final verdictLength = arena<ffi.Size>();
      final evidence = arena<ffi.Pointer<ffi.Uint8>>();
      final evidenceLength = arena<ffi.Size>();
      final code = verify(
        body.ptr,
        body.len,
        sig.ptr,
        sig.len,
        key.ptr,
        key.len,
        address.ptr,
        address.len,
        verdict,
        verdictLength,
        evidence,
        evidenceLength,
      );
      final details = _takeSecurityEvidence(
        evidence.value,
        evidenceLength.value,
      );
      final bytes = _take(verdict.value, verdictLength.value);
      if (code != 0) throw ScommSmimeException(code, _readLastError());
      return (
        verdict: SmimeSignatureVerdict.fromJson(
          jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>,
        ),
        evidence: details,
      );
    });
  }

  ({SmimeDecryptResult result, Map<String, Object?>? evidence})
      decryptWithDetails({
    required List<int> ciphertext,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    final open = _detailsDecrypt;
    if (open == null) {
      return (
        result: decryptWithFormat(
          ciphertext: ciphertext,
          privateKey: privateKey,
          passphrase: passphrase,
        ),
        evidence: null,
      );
    }
    return using((arena) {
      final ct = _copy(arena, ciphertext);
      final key = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final plaintext = arena<ffi.Pointer<ffi.Uint8>>();
      final plaintextLength = arena<ffi.Size>();
      final format = arena<ffi.Pointer<ffi.Uint8>>();
      final formatLength = arena<ffi.Size>();
      final evidence = arena<ffi.Pointer<ffi.Uint8>>();
      final evidenceLength = arena<ffi.Size>();
      final code = open(
        ct.ptr,
        ct.len,
        key.ptr,
        key.len,
        pass.ptr,
        pass.len,
        plaintext,
        plaintextLength,
        format,
        formatLength,
        evidence,
        evidenceLength,
      );
      final details = _takeSecurityEvidence(
        evidence.value,
        evidenceLength.value,
      );
      final bytes = _take(plaintext.value, plaintextLength.value);
      final formatBytes = _take(format.value, formatLength.value);
      if (code != 0) {
        throw ScommSmimeException(code, _readLastError(), evidence: details);
      }
      final meta = jsonDecode(utf8.decode(formatBytes)) as Map<String, dynamic>;
      return (
        result: SmimeDecryptResult(
          plaintext: Uint8List.fromList(bytes),
          format: meta['format'] as String? ?? '',
          algorithm: meta['algorithm'] as String? ?? '',
        ),
        evidence: details,
      );
    });
  }

  List<int> _take(ffi.Pointer<ffi.Uint8> ptr, int len) {
    if (ptr == ffi.nullptr || len == 0) return const [];
    final bytes = ptr.asTypedList(len).toList(growable: false);
    _bufferFree(ptr, len);
    return bytes;
  }

  static ({ffi.Pointer<ffi.Uint8> ptr, int len}) _copy(
    ffi.Allocator arena,
    List<int> bytes,
  ) {
    if (bytes.isEmpty) {
      return (ptr: ffi.nullptr, len: 0);
    }
    final ptr = arena<ffi.Uint8>(bytes.length);
    ptr.asTypedList(bytes.length).setAll(0, bytes);
    return (ptr: ptr, len: bytes.length);
  }

  static Uint8List _encodeRecipients(List<List<int>> keys) {
    var total = 4;
    for (final k in keys) {
      total += 4 + k.length;
    }
    final out = ByteData(total);
    var o = 0;
    out.setUint32(o, keys.length, Endian.big);
    o += 4;
    for (final k in keys) {
      out.setUint32(o, k.length, Endian.big);
      o += 4;
      out.buffer.asUint8List().setRange(o, o + k.length, k);
      o += k.length;
    }
    return out.buffer.asUint8List();
  }

  static ffi.DynamicLibrary _open() => ScommOpenPgp.instance.library;
}
