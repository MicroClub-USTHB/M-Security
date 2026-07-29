// Public API wrapper for Argon2id hashing with platform-aware defaults.
// Uses bool.fromEnvironment for compile-time preset selection.

import 'dart:convert';

import '../rust/api/hashing/argon2.dart' as ffi;
import '../rust/core/error.dart';

export '../rust/api/hashing/argon2.dart' show Argon2Preset;

/// Largest password [argon2IdVerify] accepts, in UTF-8 bytes.
const int maxArgon2VerifyPasswordBytes = 1024;

// Compile-time flag: pass -DIS_DESKTOP=true for desktop/server builds
const bool _isDesktop = bool.fromEnvironment('IS_DESKTOP');

const ffi.Argon2Preset _defaultPreset = _isDesktop
    ? ffi.Argon2Preset.desktop
    : ffi.Argon2Preset.mobile;

/// Hash a password using Argon2id.
///
/// [preset] defaults to [Argon2Preset.desktop] on desktop builds
/// (compiled with `-DIS_DESKTOP=true`) and [Argon2Preset.mobile] otherwise.
Future<String> argon2IdHash({
  required String password,
  ffi.Argon2Preset preset = _defaultPreset,
}) => ffi.argon2IdHash(password: password, preset: preset);

/// Hash a password using Argon2id with an explicit salt.
///
/// [preset] defaults based on the build target (see [argon2IdHash]).
Future<String> argon2IdHashWithSalt({
  required String password,
  required String salt,
  ffi.Argon2Preset preset = _defaultPreset,
}) => ffi.argon2IdHashWithSalt(password: password, salt: salt, preset: preset);

/// Verify a password against an Argon2id PHC hash string.
///
/// Throws [CryptoError.argon2PolicyViolation] if the password is longer than
/// [maxArgon2VerifyPasswordBytes]. The native side applies the same ceiling,
/// along with the limits on the hash itself.
Future<void> argon2IdVerify({
  required String phcHash,
  required String password,
}) async {
  // UTF-8 never spends fewer bytes than the string has UTF-16 code units, so
  // the cheap length test runs first and keeps the encoding below it bounded.
  if (password.length > maxArgon2VerifyPasswordBytes ||
      utf8.encode(password).length > maxArgon2VerifyPasswordBytes) {
    throw CryptoError.argon2PolicyViolation(
      'password is longer than $maxArgon2VerifyPasswordBytes UTF-8 bytes',
    );
  }

  return ffi.argon2IdVerify(phcHash: phcHash, password: password);
}
