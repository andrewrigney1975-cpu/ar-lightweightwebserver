// Windows Service plumbing and the install / uninstall / run / open-admin commands.
#pragma once

#include <string>

namespace wsrv {

int RunAsService();
int RunInConsole(const std::wstring& dataDir, bool openBrowser);
int Install();
int Uninstall(bool purge);
int OpenAdmin();
int PrintStatus();

} // namespace wsrv
