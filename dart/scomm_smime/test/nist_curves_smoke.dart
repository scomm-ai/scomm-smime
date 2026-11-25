// Run with a shared library built from both SDKs in SCOMM_OPENPGP_LIB.
import 'dart:convert';
import '../lib/scomm_smime.dart';

void main(List<String> args) {
  final sdk = ScommSmime.instance;
  if (args.contains('--expect-unsupported')) {
    if (sdk.supportsNistCurves) throw StateError('Expected an older library');
    try {
      sdk.generateKey(
          userid: 'curves@example.com', profile: SmimeKeyProfile.classicalP256);
    } on StateError {
      print('Older S/MIME library correctly refused NIST curves');
      return;
    }
    throw StateError('Older library did not reject NIST curves');
  }
  if (!sdk.supportsNistCurves) throw StateError('S/MIME ABI 8 required');
  final data = utf8.encode('Dart native NIST curves');
  for (final (profile, algorithm) in [
    (SmimeKeyProfile.classicalP256, 'smime-ecdsa-p256-sha256'),
    (SmimeKeyProfile.classicalP384, 'smime-ecdsa-p384-sha384'),
    (SmimeKeyProfile.classicalP521, 'smime-ecdsa-p521-sha512'),
  ]) {
    final key = sdk.generateKey(
        userid: 'Curves <curves@example.com>',
        profile: profile,
        validityYears: 2);
    final sig = sdk.signDetached(
        data: data, privateKey: key.secret, algorithm: algorithm);
    if (!sdk.verify(data: data, signature: sig, publicKey: key.public))
      throw StateError('Signature failed: $profile');
    final encrypted =
        sdk.encrypt(plaintext: data, recipientPublicKeys: [key.public]);
    if (utf8.decode(
            sdk.decrypt(ciphertext: encrypted, privateKey: key.secret)) !=
        utf8.decode(data)) throw StateError('Decryption failed: $profile');
    print('S/MIME $profile passed');
  }
}
