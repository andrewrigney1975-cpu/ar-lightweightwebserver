#include "service.h"

#include "certs.h"
#include "config_store.h"
#include "httpsys.h"
#include "log.h"
#include "pipe.h"
#include "reconciler.h"
#include "server.h"
#include "util.h"

#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cstdio>

namespace wsrv {

namespace {

constexpr const wchar_t* kDisplayName = L"wsrv web server";
constexpr const wchar_t* kDescription =
    L"Lightweight HTTPS / HTTP/3 static web server for local folders. Manage at https://local.admin:8192";
constexpr const wchar_t* kEventLogKey = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\wsrv";
constexpr const wchar_t* kHttpParamsKey = L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters";

void WriteStd(DWORD which, const std::string& line) {
    std::wstring w = FromUtf8(line);
    DWORD n = 0;
    HANDLE out = GetStdHandle(which);
    // WriteConsoleW fails when redirected to a file or pipe; fall back to UTF-8 bytes.
    if (!WriteConsoleW(out, w.data(), (DWORD)w.size(), &n, nullptr)) WriteFile(out, line.data(), (DWORD)line.size(), &n, nullptr);
}

void Print(const std::string& s) { WriteStd(STD_OUTPUT_HANDLE, s + "\r\n"); }
void PrintErr(const std::string& s) { WriteStd(STD_ERROR_HANDLE, "error: " + s + "\r\n"); }

std::wstring KnownFolder(REFKNOWNFOLDERID id, const wchar_t* fallback) {
    PWSTR p = nullptr;
    std::wstring out = fallback;
    if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) out = p;
    CoTaskMemFree(p);
    return out;
}

std::wstring InstallDir() { return KnownFolder(FOLDERID_ProgramFiles, L"C:\\Program Files") + L"\\wsrv"; }
std::wstring ShortcutPath() { return KnownFolder(FOLDERID_CommonPrograms, L"") + L"\\wsrv Admin.lnk"; }

bool RequireElevation() {
    if (IsElevated()) return true;
    PrintErr("this command must be run from an elevated (Administrator) prompt.");
    return false;
}

struct ScHandle {
    SC_HANDLE h = nullptr;
    ~ScHandle() { if (h) CloseServiceHandle(h); }
};

DWORD ServiceState(SC_HANDLE svc) {
    SERVICE_STATUS_PROCESS st{};
    DWORD n = 0;
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&st), sizeof st, &n)) return 0;
    return st.dwCurrentState;
}

bool WaitForState(SC_HANDLE svc, DWORD state, DWORD timeoutMs) {
    for (DWORD waited = 0; waited < timeoutMs; waited += 250) {
        if (ServiceState(svc) == state) return true;
        Sleep(250);
    }
    return ServiceState(svc) == state;
}

void StopService(SC_HANDLE svc) {
    if (ServiceState(svc) == SERVICE_STOPPED) return;
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    WaitForState(svc, SERVICE_STOPPED, 30000);
}

bool SetHttpParam(const wchar_t* name, DWORD value, bool& changed) {
    auto cur = ReadHttpParameter(name);
    if (cur && *cur == value) return true;
    HKEY key;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kHttpParamsKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;
    LSTATUS r = RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof value);
    RegCloseKey(key);
    if (r == ERROR_SUCCESS) changed = true;
    return r == ERROR_SUCCESS;
}

void RegisterEventSource(const std::wstring& exe) {
    HKEY key;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kEventLogKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExW(key, L"EventMessageFile", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(exe.c_str()),
                   DWORD((exe.size() + 1) * sizeof(wchar_t)));
    DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    RegSetValueExW(key, L"TypesSupported", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&types), sizeof types);
    RegCloseKey(key);
}

bool CreateShortcut(const std::wstring& exe) {
    HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool ok = false;
    IShellLinkW* link = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link)))) {
        link->SetPath(exe.c_str());
        link->SetArguments(L"open-admin");
        link->SetDescription(L"Manage wsrv web roots");
        link->SetShowCmd(SW_SHOWMINNOACTIVE);
        IPersistFile* file = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_PPV_ARGS(&file)))) {
            ok = SUCCEEDED(file->Save(ShortcutPath().c_str(), TRUE));
            file->Release();
        }
        link->Release();
    }
    if (SUCCEEDED(init)) CoUninitialize();
    return ok;
}

void DeleteTree(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring full = dir + L"\\" + name;
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                DeleteTree(full);
            else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveDirectoryW(full.c_str());
            else {
                SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(full.c_str());
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

// ------------------------------------------------------------------------------------------
// Service runtime

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stopEvent = nullptr;

void Report(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkpoint = 1;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI ControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        Report(SERVICE_STOP_PENDING, NO_ERROR, 15000);
        SetEvent(g_stopEvent);
        return NO_ERROR;
    }
    return control == SERVICE_CONTROL_INTERROGATE ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ControlHandler, nullptr);
    if (!g_statusHandle) return;
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Report(SERVICE_START_PENDING, NO_ERROR, 30000);

    std::wstring dataDir = DefaultDataDir();
    log::Init({false, true, dataDir + L"\\logs"});
    {
        Server server;
        std::string err;
        if (!server.Start({dataDir, L""}, &err)) {
            log::Error("Startup failed: " + err);
            server.Stop();
            log::Shutdown();
            Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
            return;
        }
        Report(SERVICE_RUNNING);
        WaitForSingleObject(g_stopEvent, INFINITE);
        server.Stop();
    }
    log::Shutdown();
    CloseHandle(g_stopEvent);
    Report(SERVICE_STOPPED);
}

HANDLE g_consoleStop = nullptr;

BOOL WINAPI ConsoleHandler(DWORD) {
    SetEvent(g_consoleStop);
    return TRUE;
}

} // namespace

int RunAsService() {
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        PrintErr("'service' is used by the Service Control Manager. Use 'wsrv run' to run in the foreground.");
        return 1;
    }
    return 0;
}

int RunInConsole(const std::wstring& dataDir, bool openBrowser) {
    if (!RequireElevation()) return 1;
    {
        ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
        ScHandle svc{scm.h ? OpenServiceW(scm.h, kServiceName, SERVICE_QUERY_STATUS) : nullptr};
        if (svc.h && ServiceState(svc.h) == SERVICE_RUNNING) {
            PrintErr("the wsrv service is running. Stop it first: sc stop wsrv");
            return 1;
        }
    }
    log::Init({true, false, dataDir + L"\\logs"});
    g_consoleStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    Server server;
    std::string err;
    if (!server.Start({dataDir, CurrentUserSidString()}, &err)) {
        log::Error("Startup failed: " + err);
        server.Stop();
        log::Shutdown();
        return 1;
    }
    std::string url = server.NewLoginUrl(600);
    Print("\nAdmin sign-in link (valid 10 minutes, single use):\n  " + url + "\n\nPress Ctrl+C to stop.\n");
    if (openBrowser) ShellExecuteW(nullptr, L"open", FromUtf8(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    WaitForSingleObject(g_consoleStop, INFINITE);
    server.Stop();
    log::Shutdown();
    return 0;
}

int Install() {
    if (!RequireElevation()) return 1;
    std::wstring dir = InstallDir();
    std::wstring target = dir + L"\\wsrv.exe";
    std::wstring self = ExePath();

    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
    if (!scm.h) { PrintErr("OpenSCManager: " + ErrorTextUtf8(GetLastError())); return 1; }
    ScHandle svc{OpenServiceW(scm.h, kServiceName, SERVICE_ALL_ACCESS)};
    if (svc.h) {
        Print("Stopping existing wsrv service...");
        StopService(svc.h);
    }

    // 1. Binary.
    CreateDirectoryW(dir.c_str(), nullptr);
    if (!EqualsNoCase(self, target) && !CopyFileW(self.c_str(), target.c_str(), FALSE)) {
        PrintErr("copy to " + ToUtf8(target) + ": " + ErrorTextUtf8(GetLastError()));
        return 1;
    }
    Print("Installed " + ToUtf8(target));

    // 2. Private data directory + owner.
    std::wstring dataDir = DefaultDataDir();
    std::string err;
    if (EnsureDataDir(dataDir, &err).empty()) { PrintErr(err); return 1; }
    {
        ConfigStore store;
        if (!store.Open(dataDir + L"\\wsrv.db", &err)) { PrintErr("database: " + err); return 1; }
        store.SetSetting("owner_sid", ToUtf8(CurrentUserSidString()));
    }
    Print("Configuration: " + ToUtf8(dataDir) + "\\wsrv.db (SYSTEM and Administrators only)");

    // 3. http.sys HTTP/3.
    bool httpChanged = false;
    if (!SetHttpParam(L"EnableHttp3", 1, httpChanged) || !SetHttpParam(L"EnableAltSvc", 1, httpChanged))
        PrintErr("could not enable HTTP/3 in http.sys registry settings");

    // 4. Event log source.
    RegisterEventSource(target);

    // 5. Service.
    std::wstring cmd = L"\"" + target + L"\" service";
    if (!svc.h) {
        svc.h = CreateServiceW(scm.h, kServiceName, kDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                               SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, L"HTTP\0", nullptr,
                               nullptr);
        if (!svc.h) { PrintErr("CreateService: " + ErrorTextUtf8(GetLastError())); return 1; }
    } else {
        ChangeServiceConfigW(svc.h, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.c_str(),
                             nullptr, nullptr, L"HTTP\0", nullptr, nullptr, kDisplayName);
    }
    SERVICE_DESCRIPTIONW desc{const_cast<LPWSTR>(kDescription)};
    ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_DESCRIPTION, &desc);
    SC_ACTION actions[] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 30000}};
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 86400;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    if (!StartServiceW(svc.h, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        PrintErr("StartService: " + ErrorTextUtf8(GetLastError()) + " (see " + ToUtf8(dataDir) + "\\logs\\wsrv.log)");
        return 1;
    }
    if (!WaitForState(svc.h, SERVICE_RUNNING, 30000)) {
        PrintErr("service did not reach RUNNING; see " + ToUtf8(dataDir) + "\\logs\\wsrv.log");
        return 1;
    }
    Print("Service 'wsrv' is running (automatic start, restarts on failure).");

    // 6. Start-menu shortcut.
    if (CreateShortcut(target)) Print("Start menu: \"wsrv Admin\"");

    Print("\nOpen the admin site with the \"wsrv Admin\" shortcut or:  wsrv open-admin");
    if (httpChanged)
        Print("\nHTTP/3 was just enabled in http.sys. It takes effect after a reboot (or after restarting the HTTP\n"
              "service, which also restarts IIS and every other http.sys-based service). Until then wsrv serves HTTP/2.");
    return 0;
}

int Uninstall(bool purge) {
    if (!RequireElevation()) return 1;
    std::wstring dir = InstallDir();
    std::wstring target = dir + L"\\wsrv.exe";

    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS)};
    ScHandle svc{scm.h ? OpenServiceW(scm.h, kServiceName, SERVICE_ALL_ACCESS) : nullptr};
    if (svc.h) {
        StopService(svc.h);
        if (DeleteService(svc.h)) Print("Service removed.");
        else PrintErr("DeleteService: " + ErrorTextUtf8(GetLastError()));
    }

    // Certificates, SNI bindings and hosts entries recorded in the database.
    std::wstring dataDir = DefaultDataDir();
    if (GetFileAttributesW((dataDir + L"\\wsrv.db").c_str()) != INVALID_FILE_ATTRIBUTES) {
        log::Init({true, false, L""});
        HttpApiScope api;
        ConfigStore store;
        std::string err;
        if (store.Open(dataDir + L"\\wsrv.db", &err)) {
            Reconciler(store, nullptr, L"").RemoveAll();
            Print("Removed wsrv certificates, TLS bindings and hosts entries.");
        } else {
            PrintErr("database: " + err);
        }
        log::Shutdown();
    }

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, kEventLogKey);
    DeleteFileW(ShortcutPath().c_str());

    if (purge) {
        DeleteTree(dataDir);
        Print("Deleted " + ToUtf8(dataDir));
    } else {
        Print("Kept configuration in " + ToUtf8(dataDir) + " (use --purge to delete it).");
    }

    if (EqualsNoCase(ExePath(), target)) {
        MoveFileExW(target.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        MoveFileExW(dir.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        Print("wsrv.exe will be removed at next reboot.");
    } else {
        DeleteFileW(target.c_str());
        RemoveDirectoryW(dir.c_str());
    }
    Print("http.sys HTTP/3 settings (EnableHttp3/EnableAltSvc) were left unchanged; other software may use them.");
    return 0;
}

int OpenAdmin() {
    std::string token, err;
    if (!RequestLoginToken(token, &err)) {
        PrintErr(err);
        MessageBoxW(nullptr, FromUtf8(err).c_str(), L"wsrv Admin", MB_OK | MB_ICONERROR);
        return 1;
    }
    std::wstring url = FromUtf8("https://local.admin:8192/login?t=" + token);
    if ((INT_PTR)ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL) <= 32) {
        PrintErr("could not open the browser");
        return 1;
    }
    return 0;
}

int PrintStatus() {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    ScHandle svc{scm.h ? OpenServiceW(scm.h, kServiceName, SERVICE_QUERY_STATUS) : nullptr};
    const char* state = "not installed";
    if (svc.h) {
        switch (ServiceState(svc.h)) {
        case SERVICE_RUNNING: state = "running"; break;
        case SERVICE_STOPPED: state = "stopped"; break;
        case SERVICE_START_PENDING: state = "starting"; break;
        case SERVICE_STOP_PENDING: state = "stopping"; break;
        default: state = "unknown";
        }
    }
    Print(std::string("wsrv ") + kVersion);
    Print(std::string("Service:      ") + state);
    auto describe = [](HttpFeatureState s) -> std::string {
        switch (s) {
        case HttpFeatureState::Enabled: return "enabled";
        case HttpFeatureState::PendingRestart: return "turned on, takes effect after a reboot";
        default: return "disabled";
        }
    };
    Print("HTTP/3:       " + describe(QueryHttpFeature(L"EnableHttp3")) + " (http.sys EnableHttp3)");
    Print("Alt-Svc:      " + describe(QueryHttpFeature(L"EnableAltSvc")) + " (http.sys EnableAltSvc)");
    Print("Data:         " + ToUtf8(DefaultDataDir()));
    Print("Admin:        https://local.admin:8192/");
    return 0;
}

} // namespace wsrv
