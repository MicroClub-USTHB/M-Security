// Public API wrapper for Argon2id hashing with platform-aware defaults.
// Uses bool.fromEnvironment for compile-time preset selection.

import '../rust/api/hashing/argon2.dart' as ffi;

export '../rust/api/hashing/argon2.dart' show Argon2Preset;

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
Future<void> argon2IdVerify({
  required String phcHash,
  required String password,
}) => ffi.argon2IdVerify(phcHash: phcHash, password: password);
