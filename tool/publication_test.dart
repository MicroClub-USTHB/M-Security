// The tree parse is the one place in the assembler that can be wrong quietly:
// a size suffix it does not recognize turns a file into a directory and the
// file leaves the payload without anything complaining. These cases pin the
// shapes pub actually prints.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'publication.dart';

const String _tree = '''
Resolving dependencies...
Got dependencies!
Publishing m_security 0.3.5 to https://pub.dev:
├── CHANGELOG.md (12 KB)
├── android
│   ├── build.gradle (1 KB)
│   ├── gradle
│   │   └── wrapper
│   │       ├── gradle-wrapper.jar (42 KB)
│   │       └── gradle-wrapper.properties (<1 KB)
│   └── settings.gradle (<1 KB)
├── ios
│   └── Assets
├── rust
│   └── src
│       ├── frb_generated.rs (202 KB)
│       └── lib.rs (<1 KB)
└── windows
    └── CMakeLists.txt (<1 KB)

Total compressed archive size: 14 MB.
Validating package...
''';

void main() {
  test('every printed file becomes a full path, in sorted order', () {
    expect(parseInclusionSet(_tree), [
      'CHANGELOG.md',
      'android/build.gradle',
      'android/gradle/wrapper/gradle-wrapper.jar',
      'android/gradle/wrapper/gradle-wrapper.properties',
      'android/settings.gradle',
      'rust/src/frb_generated.rs',
      'rust/src/lib.rs',
      'windows/CMakeLists.txt',
    ]);
  });

  test('a childless directory contributes no file', () {
    expect(parseInclusionSet(_tree), isNot(contains('ios/Assets')));
    expect(parseInclusionSet(_tree), isNot(contains('ios')));
  });

  test('sizes pub prints are all recognized as sizes', () {
    // The four shapes pub's own `_readableFileSize` can produce.
    const sizes = ['<1 KB', '1 KB', '202 KB', '14 MB', '3 GB'];
    for (final size in sizes) {
      final tree =
          'Publishing p 1.0.0 to https://pub.dev:\n'
          '└── file.bin ($size)\n'
          'Total compressed archive size: 1 MB.\n';
      expect(parseInclusionSet(tree), ['file.bin'], reason: size);
    }
  });

  test('a tree with no files parses to nothing rather than to a directory', () {
    const tree =
        'Publishing p 1.0.0 to https://pub.dev:\n'
        '└── empty_dir\n'
        'Total compressed archive size: 1 MB.\n';
    expect(parseInclusionSet(tree), isEmpty);
  });

  test('output without a tree parses to nothing', () {
    expect(parseInclusionSet('Resolving dependencies...\nGot it!\n'), isEmpty);
  });

  // No path in this package is long enough to reach the prefix split, and
  // assembling the payload is the only other thing that exercises the header,
  // so the branch would otherwise ship unrun.
  group('ustar headers', () {
    String field(List<int> header, int offset, int length) =>
        utf8.decode(header.sublist(offset, offset + length)).split('\u0000')[0];

    test('a short path stays in the name field', () {
      final header = tarHeader('rust/src/lib.rs', 265, 420);

      expect(field(header, 0, 100), 'rust/src/lib.rs');
      expect(field(header, 345, 155), '');
      expect(field(header, 100, 8), '0000644');
      expect(field(header, 124, 12), '00000000411');
      expect(field(header, 257, 6), 'ustar');
      expect(header[156], 0x30);
    });

    test('a long path splits across prefix and name', () {
      final long = '${List.filled(12, 'directory').join('/')}/file.dart';
      expect(long.length, greaterThan(100));

      final header = tarHeader(long, 1, 493);

      expect(field(header, 0, 100), 'file.dart');
      expect(field(header, 345, 155), List.filled(12, 'directory').join('/'));
      expect(field(header, 100, 8), '0000755');
    });

    test('the checksum covers the header with its own field blanked', () {
      final header = tarHeader('a.txt', 3, 420);
      final blanked = [...header];
      blanked.setRange(148, 156, utf8.encode('        '));

      final sum = blanked.fold<int>(0, (total, byte) => total + byte);
      expect(field(header, 148, 6), sum.toRadixString(8).padLeft(6, '0'));
      expect(header[154], 0);
      expect(header[155], 0x20);
    });
  });
}
