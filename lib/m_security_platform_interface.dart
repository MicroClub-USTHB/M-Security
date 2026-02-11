import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'm_security_method_channel.dart';

abstract class MSecurityPlatform extends PlatformInterface {
  /// Constructs a MSecurityPlatform.
  MSecurityPlatform() : super(token: _token);

  static final Object _token = Object();

  static MSecurityPlatform _instance = MethodChannelMSecurity();

  /// The default instance of [MSecurityPlatform] to use.
  ///
  /// Defaults to [MethodChannelMSecurity].
  static MSecurityPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [MSecurityPlatform] when
  /// they register themselves.
  static set instance(MSecurityPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
