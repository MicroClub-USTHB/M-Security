// Build a throwaway app against an assembled publish payload and run the
// containment subset on it.
//
//   dart run tool/packaged_consumer.dart \
//     --payload <dir> --out <dir> --device linux --min-tests 20
//
// The point is that nothing here reaches back into the checkout. The consumer
// lives outside the repository, depends on the payload by path, takes its test
// file out of the payload, and links the native library the payload's own Rust
// sources produce. What it proves is what a `pub get` of this release would
// give somebody.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

const String _usage =
    'usage: dart run tool/packaged_consumer.dart --payload <dir> --out <dir> '
    '[--device linux] [--min-tests 1]';

const String _projectName = 'm_security_consumer';
const String _entrypoint = 'example/integration_test/containment_test.dart';

/// Native entries this release removed. None may appear in the built library.
const List<String> _removedSymbols = [
  'create_noop_encryption',
  'vault_export',
  'vault_import',
  'stream_encrypt_file',
  'stream_decrypt_file',
  'stream_compress_encrypt_file',
  'stream_decrypt_decompress_file',
];

/// Entries that must survive, so an empty or unreadable symbol table cannot
/// pass the check above by accident.
const List<String> _keptSymbols = [
  'create_aes256_gcm',
  'create_chacha20_poly1305',
  'vault_create',
  'stream_hash_file',
];

Future<void> main(List<String> args) async {
  final options = _Options.parse(args);

  final entrypoint = File('${options.payload}/$_entrypoint');
  if (!entrypoint.existsSync()) {
    _fail('the payload has no $_entrypoint');
  }
  if (!File('${options.payload}/pubspec.yaml').existsSync()) {
    _fail('${options.payload} does not look like a package payload');
  }

  final consumer = Directory(options.out);
  if (consumer.existsSync()) consumer.deleteSync(recursive: true);
  consumer.createSync(recursive: true);

  await _run('flutter', [
    'create',
    '--template=app',
    '--platforms=${options.device}',
    '--project-name',
    _projectName,
    consumer.path,
  ], consumer.parent.path);

  File('${consumer.path}/pubspec.yaml').writeAsStringSync(
    _consumerPubspec(options.payload),
  );
  // The generated options file includes a lint package the pubspec above
  // drops, and an unresolved include is an analysis error in its own right.
  final generatedOptions = File('${consumer.path}/analysis_options.yaml');
  if (generatedOptions.existsSync()) generatedOptions.deleteSync();
  Directory('${consumer.path}/integration_test').createSync(recursive: true);
  File(
    '${consumer.path}/integration_test/containment_test.dart',
  ).writeAsBytesSync(entrypoint.readAsBytesSync());

  await _run('flutter', ['pub', 'get'], consumer.path);
  await _checkRemovedSurfaceIsUnresolvable(consumer.path);

  final report = await _runContainmentTests(consumer.path, options);
  final problems = _verdict(report, options.minTests);

  // The symbol scan and the report are what a failing run most needs, so they
  // happen before the verdict is acted on rather than after.
  final native = _findNativeLibrary(Directory('${consumer.path}/build'));
  final symbols = native == null
      ? <String, Object?>{'error': 'no built m_security library'}
      : await _checkSymbols(native);

  final payloadReport = File('${options.payload}.report.json');
  final result = <String, Object?>{
    'payload_dir': options.payload,
    'payload_report': payloadReport.existsSync() ? payloadReport.path : null,
    'consumer_dir': consumer.path,
    'device': options.device,
    'command':
        'flutter test integration_test/containment_test.dart '
        '-d ${options.device} --machine',
    'flutter': (await _capture(
      'flutter',
      ['--version'],
      consumer.path,
    )).split('\n').first,
    'dart': await _capture('dart', ['--version'], consumer.path),
    'rustc': await _capture('rustc', ['--version'], consumer.path),
    'native_library': native?.path,
    'native_digest': native == null
        ? null
        : sha256.convert(native.readAsBytesSync()).toString(),
    'symbol_scan': symbols,
    'tests_executed': report.executed,
    'tests_failed': report.failed,
    'tests_skipped': report.skipped,
    'problems': problems,
  };
  if (options.report != null) {
    File(options.report!).writeAsStringSync(
      '${const JsonEncoder.withIndent('  ').convert(result)}\n',
    );
  }

  stdout
    ..writeln('tests executed  ${report.executed}')
    ..writeln('tests failed    ${report.failed}')
    ..writeln('tests skipped   ${report.skipped}')
    ..writeln('native library  ${native?.path}')
    ..writeln('native digest   ${result['native_digest']}')
    ..writeln('symbol scan     $symbols');

  if (native == null) {
    problems.add('no built m_security library under ${consumer.path}/build');
  } else if (symbols['ok'] != true) {
    problems.add('the symbol scan did not pass: ${symbols['error']}');
  }
  if (problems.isNotEmpty) {
    _fail('the packaged run did not pass:\n'
        '${problems.map((p) => '  $p').join('\n')}');
  }
}

class _Options {
  const _Options({
    required this.payload,
    required this.out,
    required this.device,
    required this.minTests,
    required this.report,
  });

  final String payload;
  final String out;
  final String device;
  final int minTests;
  final String? report;

  static _Options parse(List<String> args) {
    String? payload;
    String? out;
    var device = 'linux';
    var minTests = 1;
    String? report;

    for (var i = 0; i < args.length; i++) {
      final next = i + 1 < args.length ? args[i + 1] : null;
      switch (args[i]) {
        case '--payload' when next != null:
          payload = args[++i];
        case '--out' when next != null:
          out = args[++i];
        case '--device' when next != null:
          device = args[++i];
        case '--min-tests' when next != null:
          minTests = int.parse(args[++i]);
        case '--report' when next != null:
          report = args[++i];
        default:
          _fail('unrecognized argument ${args[i]}\n$_usage');
      }
    }
    if (payload == null || out == null) _fail(_usage);
    if (minTests < 1) _fail('--min-tests must be at least 1');

    // A trailing slash would put the sibling report under a dot name.
    String trim(String path) => path.replaceFirst(RegExp(r'/+$'), '');

    return _Options(
      payload: Directory(trim(payload)).absolute.path,
      out: Directory(trim(out)).absolute.path,
      device: device,
      minTests: minTests,
      report: report == null ? null : File(report).absolute.path,
    );
  }
}

String _consumerPubspec(String payloadPath) =>
    '''
name: $_projectName
description: Runs the containment subset against an assembled publish payload.
publish_to: none
version: 0.0.0

environment:
  sdk: ^3.10.8

dependencies:
  flutter:
    sdk: flutter
  m_security:
    path: $payloadPath

dev_dependencies:
  flutter_test:
    sdk: flutter
  integration_test:
    sdk: flutter

flutter:
  uses-material-design: true
''';

/// Write a file that calls the entries this release removed, prove it does not
/// analyze, then delete it and prove the rest of the consumer does.
///
/// This is the case a symbol scan cannot make: a consumer that reaches past the
/// package barrel straight at the generated bindings still has nothing to call.
///
/// The trap to avoid is the fixture failing for the wrong reason. A payload
/// missing `lib/src/rust/` entirely would produce the same undefined-function
/// errors, so an unresolved import is treated as a failure of the check rather
/// than a pass, and a positive fixture runs first to establish that the
/// package's own libraries resolve at all.
Future<void> _checkRemovedSurfaceIsUnresolvable(String consumerDir) async {
  final positive = File('$consumerDir/lib/present_surface_fixture.dart');
  positive.writeAsStringSync('''
// Temporary. Everything here survives this release, so this file must analyze.
import 'package:m_security/m_security.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/api/evfs.dart';
import 'package:m_security/src/rust/api/streaming.dart';

Future<void> reachKeptEntries() async {
  await RustLib.init();
  final cipher = await createAes256Gcm(key: await generateAes256GcmKey());
  await createChacha20Poly1305(key: await generateChacha20Poly1305Key());
  await vaultCreate(
    path: 'v',
    key: await generateAes256GcmKey(),
    algorithm: 'aes-256-gcm',
    capacityBytes: BigInt.one,
    unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.deny,
  );
  streamHashFile(hasher: await createBlake3(), filePath: 'f');
  cipher.dispose();
}
''');

  final withPositive = await Process.run(
    'dart',
    ['analyze', '--no-fatal-warnings', positive.path],
    workingDirectory: consumerDir,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  final positiveOutput = '${withPositive.stdout}${withPositive.stderr}';
  positive.deleteSync();
  if (withPositive.exitCode != 0) {
    _fail(
      'the payload\'s own libraries do not resolve from a clean consumer, so '
      'the removed-entry check below would pass for the wrong reason:\n'
      '$positiveOutput',
    );
  }

  final fixture = File('$consumerDir/lib/removed_surface_fixture.dart');
  fixture.writeAsStringSync('''
// Temporary. Every call below names an entry this release removed, so this
// file must not analyze.
import 'dart:typed_data';

import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/api/evfs.dart';
import 'package:m_security/src/rust/api/streaming.dart';

Future<void> reachRemovedEntries(CipherHandle cipher, Uint8List key) async {
  await createNoopEncryption();
  await vaultExport(handle: cipher, wrappingKey: key, exportPath: 'out.mvex');
  await vaultImport(archivePath: 'in.mvex', wrappingKey: key);
  streamEncryptFile(cipher: cipher, inputPath: 'a', outputPath: 'b');
  streamDecryptFile(cipher: cipher, inputPath: 'a', outputPath: 'b');
  streamCompressEncryptFile(cipher: cipher, inputPath: 'a', outputPath: 'b');
  streamDecryptDecompressFile(cipher: cipher, inputPath: 'a', outputPath: 'b');
}
''');

  final withFixture = await Process.run(
    'dart',
    ['analyze', '--no-fatal-warnings', fixture.path],
    workingDirectory: consumerDir,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  final output = '${withFixture.stdout}${withFixture.stderr}';
  fixture.deleteSync();

  if (withFixture.exitCode == 0) {
    _fail('a consumer can still resolve the removed entries:\n$output');
  }
  if (output.contains("Target of URI doesn't exist")) {
    _fail(
      'the negative fixture failed on an import rather than on the removed '
      'entries:\n$output',
    );
  }
  for (final name in [
    'createNoopEncryption',
    'vaultExport',
    'vaultImport',
    'streamEncryptFile',
    'streamDecryptFile',
    'streamCompressEncryptFile',
    'streamDecryptDecompressFile',
  ]) {
    if (!output.contains(name)) {
      _fail(
        'the negative fixture failed without naming $name, so the failure may '
        'not be the one it is testing for:\n$output',
      );
    }
  }

  // Without the fixture the same consumer has to be clean, otherwise the
  // failure above proves nothing about the removed entries.
  final clean = await Process.run(
    'dart',
    ['analyze', 'lib'],
    workingDirectory: consumerDir,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  if (clean.exitCode != 0) {
    _fail('the consumer does not analyze on its own:\n'
        '${clean.stdout}${clean.stderr}');
  }
}

class _TestReport {
  const _TestReport({
    required this.executed,
    required this.failed,
    required this.skipped,
    required this.exitCode,
    required this.errors,
  });

  final int executed;
  final int failed;
  final int skipped;
  final int exitCode;
  final List<String> errors;
}

Future<_TestReport> _runContainmentTests(
  String consumerDir,
  _Options options,
) async {
  final process = await Process.start('flutter', [
    'test',
    'integration_test/containment_test.dart',
    '-d',
    options.device,
    '--machine',
  ], workingDirectory: consumerDir);

  // Forwarded as it arrives. A build failure shows up here and nowhere in the
  // JSON events, which say only that loading the test failed.
  final drainedStderr = process.stderr
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .forEach(stderr.writeln);

  var executed = 0;
  var failed = 0;
  var skipped = 0;
  final failures = <String>[];
  final names = <int, String>{};

  await for (final line in process.stdout
      .transform(utf8.decoder)
      .transform(const LineSplitter())) {
    Object? decoded;
    try {
      decoded = jsonDecode(line);
    } on FormatException {
      stdout.writeln(line); // Flutter's own progress output, not an event.
      continue;
    }
    if (decoded is! Map<String, Object?>) continue;

    switch (decoded['type']) {
      case 'testStart':
        final test = decoded['test'] as Map<String, Object?>;
        names[test['id'] as int] = test['name'] as String;
      case 'testDone':
        if (decoded['hidden'] == true) continue;
        // A skipped test reports success, so counting it as executed would let
        // a `skip:` on a group satisfy the floor with nothing run.
        if (decoded['skipped'] == true) {
          skipped++;
          continue;
        }
        executed++;
        if (decoded['result'] != 'success') {
          failed++;
          failures.add(names[decoded['testID'] as int] ?? 'test');
        }
      case 'error':
        failures.add('${decoded['error']}');
    }
  }
  final code = await process.exitCode;
  await drainedStderr;

  stdout.writeln(
    'executed $executed test(s), $failed failed, $skipped skipped',
  );
  for (final failure in failures) {
    stdout.writeln('  failure: $failure');
  }
  return _TestReport(
    executed: executed,
    failed: failed,
    skipped: skipped,
    exitCode: code,
    errors: failures,
  );
}

/// Everything that makes a run unacceptable, as text, so the caller can write
/// its report before stopping.
List<String> _verdict(_TestReport report, int minTests) => [
  if (report.executed == 0)
    'no containment test ran, so nothing about the payload was checked',
  if (report.executed > 0 && report.executed < minTests)
    'only ${report.executed} of at least $minTests tests ran',
  if (report.skipped > 0) '${report.skipped} test(s) were skipped',
  if (report.failed > 0) '${report.failed} test(s) failed',
  // Errors arrive without a failing test attached, so they would otherwise
  // leave the counts at zero.
  for (final error in report.errors) 'reported error: $error',
  if (report.exitCode != 0) 'flutter test exited ${report.exitCode}',
];

/// The shared library the consumer's build produced.
///
/// A build tree can hold more than one match, so the candidates are sorted and
/// the shared object is preferred over a framework binary. Whichever is used
/// ends up in the report by path, so there is no guessing after the fact.
File? _findNativeLibrary(Directory buildDir) {
  if (!buildDir.existsSync()) return null;
  final candidates = <File>[];
  for (final entity in buildDir.listSync(recursive: true, followLinks: false)) {
    if (entity is! File) continue;
    final name = entity.uri.pathSegments.last;
    if (name == 'libm_security.so' ||
        name == 'libm_security.dylib' ||
        (name == 'm_security' && entity.path.contains('.framework/'))) {
      candidates.add(entity);
    }
  }
  if (candidates.isEmpty) return null;

  int rank(File file) {
    final name = file.uri.pathSegments.last;
    if (name == 'libm_security.so') return 0;
    if (name == 'libm_security.dylib') return 1;
    return 2;
  }

  candidates.sort((a, b) {
    final byRank = rank(a).compareTo(rank(b));
    return byRank != 0 ? byRank : a.path.compareTo(b.path);
  });
  return candidates.first;
}

/// Read the built library's exports and check the removed entries are gone.
///
/// The dynamic table is the one a consumer can reach, and on ELF targets the
/// crate narrows it with a version script, so it is asked for first. Mach-O
/// has no separate dynamic table, so there the global table is what there is.
Future<Map<String, Object?>> _checkSymbols(File native) async {
  var mode = '-D';
  var result = await Process.run(
    'nm',
    ['-D', '--defined-only', native.path],
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  if (result.exitCode != 0 || (result.stdout as String).trim().isEmpty) {
    mode = '-g';
    result = await Process.run(
      'nm',
      ['-g', '--defined-only', native.path],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
  }
  if (result.exitCode != 0) {
    return {'ok': false, 'error': 'nm could not read the library'};
  }
  final table = (result.stdout as String).toLowerCase();

  final missing = _keptSymbols.where((s) => !table.contains(s)).toList();
  final present = _removedSymbols.where(table.contains).toList();
  return {
    'ok': missing.isEmpty && present.isEmpty,
    'nm_mode': mode,
    'kept_missing': missing,
    'removed_present': present,
    if (missing.isNotEmpty)
      'error': 'the library does not export ${missing.join(', ')}, so an '
          'absence check against it would prove nothing',
    if (present.isNotEmpty)
      'error': 'the library still exports ${present.join(', ')}',
  };
}

Future<void> _run(
  String executable,
  List<String> args,
  String workingDirectory,
) async {
  final result = await Process.run(
    executable,
    args,
    workingDirectory: workingDirectory,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  if (result.exitCode != 0) {
    _fail(
      '$executable ${args.join(' ')} exited ${result.exitCode}:\n'
      '${result.stdout}${result.stderr}',
    );
  }
}

Future<String> _capture(
  String executable,
  List<String> args,
  String workingDirectory,
) async {
  final result = await Process.run(
    executable,
    args,
    workingDirectory: workingDirectory,
    stdoutEncoding: utf8,
    stderrEncoding: utf8,
  );
  if (result.exitCode != 0) {
    _fail('$executable ${args.join(' ')} exited ${result.exitCode}');
  }
  return (result.stdout as String).trim();
}

Never _fail(String message) {
  stderr.writeln('packaged_consumer: $message');
  exit(1);
}
