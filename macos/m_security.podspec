#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint m_security.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'm_security'
  s.version          = '0.3.5'
  s.summary          = 'A high-performance cryptographic SDK for Flutter powered by native Rust via FFI.'
  s.description      = <<-DESC
A high-performance cryptographic SDK for Flutter powered by native Rust via FFI.
Provides authenticated encryption (AES-256-GCM, ChaCha20-Poly1305), modern hashing
(BLAKE3, SHA-3, Argon2id), and key derivation (HKDF-SHA256) with secure memory management.
                       DESC
  s.homepage         = 'https://github.com/MicroClub-USTHB/M-Security'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'MicroClub-USTHB' => 'https://github.com/MicroClub-USTHB' }

  # This will ensure the source files in Classes/ are included in the native
  # builds of apps using this FFI plugin. Podspec does not support relative
  # paths, so Classes contains a forwarder C file that relatively imports
  # `../src/*` so that the C sources can be shared among all target platforms.
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.11'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'

  s.script_phase = {
    :name => 'Build Rust library',
    # First argument is relative path to the `rust` folder, second is name of rust library
    :script => 'sh "$PODS_TARGET_SRCROOT/../cargokit/build_pod.sh" ../rust m_security',
    :execution_position => :before_compile,
    :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
    # Let XCode know that the static library referenced in -force_load below is
    # created by this build step.
    :output_files => ["${BUILT_PRODUCTS_DIR}/libm_security.a"],
  }
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    # Flutter.framework does not contain a i386 slice.
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/libm_security.a',
  }
end
