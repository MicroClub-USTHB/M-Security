#include "include/m_security/m_security_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "m_security_plugin.h"

void MSecurityPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  m_security::MSecurityPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
