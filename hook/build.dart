import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    // NOTE: frb loads the lib by path, not through @Native, so the asset name
    // is just a unique id. any string works here
    await RustBuilder(
      assetName: 'src/rust/frb_generated.dart',
    ).run(input: input, output: output);
  });
}
