#ifndef FLUTTER_PLUGIN_M_SECURITY_PLUGIN_H_
#define FLUTTER_PLUGIN_M_SECURITY_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace m_security {

class MSecurityPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  MSecurityPlugin();

  virtual ~MSecurityPlugin();

  // Disallow copy and assign.
  MSecurityPlugin(const MSecurityPlugin&) = delete;
  MSecurityPlugin& operator=(const MSecurityPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace m_security

#endif  // FLUTTER_PLUGIN_M_SECURITY_PLUGIN_H_
