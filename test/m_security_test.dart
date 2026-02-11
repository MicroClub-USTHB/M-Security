import 'package:flutter_test/flutter_test.dart';
import 'package:m_security/m_security.dart';
import 'package:m_security/m_security_platform_interface.dart';
import 'package:m_security/m_security_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockMSecurityPlatform
    with MockPlatformInterfaceMixin
    implements MSecurityPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final MSecurityPlatform initialPlatform = MSecurityPlatform.instance;

  test('$MethodChannelMSecurity is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelMSecurity>());
  });

  test('getPlatformVersion', () async {
    MSecurity mSecurityPlugin = MSecurity();
    MockMSecurityPlatform fakePlatform = MockMSecurityPlatform();
    MSecurityPlatform.instance = fakePlatform;

    expect(await mSecurityPlugin.getPlatformVersion(), '42');
  });
}
