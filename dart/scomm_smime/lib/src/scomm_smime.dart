import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'types.dart';

typedef _AbiVersionN = ffi.Uint32 Function();
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
        _sign = _lib.lookupFunction<_SignN, _SignD>('scomm_smime_sign'),
        _verify = _lib.lookupFunction<_VerifyN, _VerifyD>(
          'scomm_smime_verify',
        ),
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
  final _SignD _sign;
  final _VerifyD _verify;
  final _InspectD _inspectMessage;
  final _TestPassD _testPass;
  final _SignD _popSign;
  final _PopHybridD _popHybrid;

  int get abiVersion => _abiVersion();

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

  GeneratedSmimeKey generateKey({
    required String userid,
    String passphrase = '',
    SmimeKeyProfile profile = SmimeKeyProfile.classical,
  }) {
    return using((arena) {
      final user = _copy(arena, utf8.encode(userid));
      final pass = _copy(arena, utf8.encode(passphrase));
      final pubPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final pubLen = arena<ffi.Size>();
      final secPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final secLen = arena<ffi.Size>();
      final jsonPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final jsonLen = arena<ffi.Size>();
      final code = _generate(
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

  Uint8List sign({
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
      final code = _sign(
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

  void testPassphrase({
    required List<int> privateKey,
    String passphrase = '',
  }) {
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

  static ffi.DynamicLibrary _open() {
    final override = Platform.environment['SCOMM_SMIME_LIB'];
    if (override != null && override.isNotEmpty) {
      return ffi.DynamicLibrary.open(override);
    }
    if (Platform.isWindows) {
      return ffi.DynamicLibrary.open('scomm_smime.dll');
    }
    if (Platform.isLinux) {
      return ffi.DynamicLibrary.open('libscomm_smime.so');
    }
    if (Platform.isMacOS) {
      return ffi.DynamicLibrary.open('libscomm_smime.dylib');
    }
    throw UnsupportedError(
      'scomm_smime has no bundled library for ${Platform.operatingSystem}',
    );
  }
}
