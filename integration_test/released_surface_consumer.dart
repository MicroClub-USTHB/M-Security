/// A consumer written the way the released storage surface documented it, kept
/// as a compile fixture.
///
/// Nothing here passes the unsafe-format policy or catches a disabled-format
/// result: that is the point. Every call has to keep resolving under the same
/// name, argument names and types, so `dart analyze` over this directory is what
/// proves existing source still builds against the patch. The tests that import
/// it are the ones that pin down what the calls now do at run time.
library;

import 'dart:typed_data';

import 'package:m_security/m_security.dart';

Future<VaultHandle> createVault({
  required String path,
  required Uint8List key,
  required String algorithm,
  required int capacityBytes,
}) {
  return VaultService.create(
    path: path,
    key: key,
    algorithm: algorithm,
    capacityBytes: capacityBytes,
  );
}

Future<VaultHandle> openVault({required String path, required Uint8List key}) {
  return VaultService.open(path: path, key: key);
}

Future<void> writeSegment({
  required VaultHandle handle,
  required String name,
  required Uint8List data,
}) {
  return VaultService.write(handle: handle, name: name, data: data);
}

Future<Uint8List> readSegment({
  required VaultHandle handle,
  required String name,
}) async {
  return (await VaultService.read(handle: handle, name: name)).data;
}

Future<void> exportArchive({
  required VaultHandle handle,
  required Uint8List wrappingKey,
  required String exportPath,
}) {
  return VaultService.export(
    handle: handle,
    wrappingKey: wrappingKey,
    exportPath: exportPath,
  );
}

Future<VaultHandle> importArchive({
  required String archivePath,
  required Uint8List wrappingKey,
  required String destPath,
  required Uint8List newMasterKey,
  required String algorithm,
  required int capacityBytes,
}) {
  return VaultService.importVault(
    archivePath: archivePath,
    wrappingKey: wrappingKey,
    destPath: destPath,
    newMasterKey: newMasterKey,
    algorithm: algorithm,
    capacityBytes: capacityBytes,
  );
}

Stream<double> encryptStream({
  required String inputPath,
  required String outputPath,
  required CipherHandle cipher,
}) {
  return StreamingService.encryptFile(
    inputPath: inputPath,
    outputPath: outputPath,
    cipher: cipher,
  );
}

Stream<double> decryptStream({
  required String inputPath,
  required String outputPath,
  required CipherHandle cipher,
}) {
  return StreamingService.decryptFile(
    inputPath: inputPath,
    outputPath: outputPath,
    cipher: cipher,
  );
}

Stream<double> compressStream({
  required String inputPath,
  required String outputPath,
  required CipherHandle cipher,
}) {
  return CompressionService.compressAndEncryptFile(
    inputPath: inputPath,
    outputPath: outputPath,
    cipher: cipher,
    config: const CompressionConfig(algorithm: CompressionAlgorithm.zstd),
  );
}

Stream<double> decompressStream({
  required String inputPath,
  required String outputPath,
  required CipherHandle cipher,
}) {
  return CompressionService.decryptAndDecompressFile(
    inputPath: inputPath,
    outputPath: outputPath,
    cipher: cipher,
  );
}

Future<Uint8List> hashWholeFile({
  required String filePath,
  required HasherHandle hasher,
}) {
  return StreamingService.hashFile(filePath: filePath, hasher: hasher);
}

/// The one call that has to be written differently to keep working.
Future<VaultHandle> createVaultWithOptIn({
  required String path,
  required Uint8List key,
  required String algorithm,
  required int capacityBytes,
}) {
  return VaultService.create(
    path: path,
    key: key,
    algorithm: algorithm,
    capacityBytes: capacityBytes,
    unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
  );
}

Future<VaultHandle> openVaultWithOptIn({
  required String path,
  required Uint8List key,
}) {
  return VaultService.open(
    path: path,
    key: key,
    unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
  );
}
