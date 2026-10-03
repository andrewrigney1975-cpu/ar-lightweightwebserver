// wsrv — lightweight HTTPS / HTTP/3 static web server for Windows, built on http.sys.
#include "service.h"
#include "util.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace wsrv;

static void Usage() {
    const wchar_t* text =
        L"wsrv - lightweight HTTPS / HTTP/3 static web server\n"
        L"\n"
        L"Usage: wsrv <command> [options]\n"
        L"\n"
        L"  install              Install and start the Windows service (elevated).\n"
        L"  uninstall [--purge]  Remove the service, certificates, bindings and hosts entries\n"
        L"                       (--purge also deletes the configuration database).\n"
        L"  open-admin           Sign in to https://local.admin:8192 in your browser.\n"
        L"  run [--data DIR] [--open]\n"
        L"                       Run in the foreground for development (elevated).\n"
        L"  status               Show service and HTTP/3 status.\n"
        L"  version              Print the version.\n";
    DWORD n = 0;
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), text, (DWORD)wcslen(text), &n, nullptr);
}

int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    std::vector<std::wstring> args(argv + 1, argv + argc);
    if (args.empty()) { Usage(); return 0; }
    const std::wstring& cmd = args[0];
    auto has = [&](const wchar_t* flag) {
        for (size_t i = 1; i < args.size(); ++i) if (args[i] == flag) return true;
        return false;
    };

    if (cmd == L"service") return RunAsService();
    if (cmd == L"run") {
        std::wstring dataDir = DefaultDataDir();
        for (size_t i = 1; i + 1 < args.size(); ++i) if (args[i] == L"--data") dataDir = args[i + 1];
        return RunInConsole(dataDir, has(L"--open"));
    }
    if (cmd == L"install") return Install();
    if (cmd == L"uninstall") return Uninstall(has(L"--purge"));
    if (cmd == L"open-admin") return OpenAdmin();
    if (cmd == L"status") return PrintStatus();
    if (cmd == L"version" || cmd == L"--version") { printf("wsrv %s\n", kVersion); return 0; }
    Usage();
    return cmd == L"help" || cmd == L"--help" || cmd == L"-h" ? 0 : 2;
}
