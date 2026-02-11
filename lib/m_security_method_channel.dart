import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'm_security_platform_interface.dart';

/// An implementation of [MSecurityPlatform] that uses method channels.
class MethodChannelMSecurity extends MSecurityPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('m_security');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
