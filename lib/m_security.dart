import 'm_security_platform_interface.dart';

class MSecurity {
  Future<String?> getPlatformVersion() {
    return MSecurityPlatform.instance.getPlatformVersion();
  }
}
