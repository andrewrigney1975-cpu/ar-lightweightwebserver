#include "log.h"

#include "util.h"
#include "messages.h"

#include <atomic>
#include <cstdio>
#include <mutex>

namespace wsrv::log {
namespace {

constexpr ULONGLONG kMaxFileBytes = 10ull * 1024 * 1024;

std::mutex g_mu;
Options g_opts;
HANDLE g_file = INVALID_HANDLE_VALUE;
HANDLE g_access = INVALID_HANDLE_VALUE;
HANDLE g_eventSource = nullptr;
std::atomic<bool> g_accessEnabled{false};

HANDLE OpenLog(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    return h;
}

// Keeps one previous generation: name.log -> name.1.log.
void RotateIfNeeded(HANDLE& h, const wchar_t* base) {
    LARGE_INTEGER size{};
    if (h == INVALID_HANDLE_VALUE || !GetFileSizeEx(h, &size) || ULONGLONG(size.QuadPart) < kMaxFileBytes) return;
    CloseHandle(h);
    std::wstring cur = g_opts.dir + L"\\" + base + L".log";
    std::wstring old = g_opts.dir + L"\\" + base + L".1.log";
    MoveFileExW(cur.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING);
    h = OpenLog(cur);
}

std::string Timestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[32];
    snprintf(buf, sizeof buf, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay, st.wHour,
             st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

void WriteLine(HANDLE h, const std::string& line) {
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD n = 0;
    WriteFile(h, line.data(), (DWORD)line.size(), &n, nullptr);
}

} // namespace

void Init(const Options& opts) {
    std::lock_guard lk(g_mu);
    g_opts = opts;
    if (!opts.dir.empty()) {
        CreateDirectoryW(opts.dir.c_str(), nullptr);
        g_file = OpenLog(opts.dir + L"\\wsrv.log");
    }
    if (opts.eventLog) g_eventSource = RegisterEventSourceW(nullptr, kServiceName);
}

void Shutdown() {
    std::lock_guard lk(g_mu);
    if (g_file != INVALID_HANDLE_VALUE) CloseHandle(g_file);
    if (g_access != INVALID_HANDLE_VALUE) CloseHandle(g_access);
    if (g_eventSource) DeregisterEventSource(g_eventSource);
    g_file = g_access = INVALID_HANDLE_VALUE;
    g_eventSource = nullptr;
}

void SetAccessLog(bool enabled) {
    std::lock_guard lk(g_mu);
    g_accessEnabled = enabled;
    if (enabled && g_access == INVALID_HANDLE_VALUE && !g_opts.dir.empty())
        g_access = OpenLog(g_opts.dir + L"\\access.log");
    if (!enabled && g_access != INVALID_HANDLE_VALUE) { CloseHandle(g_access); g_access = INVALID_HANDLE_VALUE; }
}

bool AccessLogEnabled() { return g_accessEnabled; }

void Write(Level level, std::string_view msg) {
    const char* tag = level == Level::Info ? "INFO " : level == Level::Warn ? "WARN " : "ERROR";
    std::string line = Timestamp() + " " + tag + " " + std::string(msg) + "\r\n";
    std::lock_guard lk(g_mu);
    if (g_opts.console) {
        std::wstring w = FromUtf8(line);
        HANDLE out = GetStdHandle(level == Level::Info ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        DWORD n = 0;
        if (!WriteConsoleW(out, w.data(), (DWORD)w.size(), &n, nullptr)) WriteLine(out, line);
    }
    RotateIfNeeded(g_file, L"wsrv");
    WriteLine(g_file, line);
    if (g_eventSource && level != Level::Info) {
        std::wstring w = FromUtf8(msg);
        LPCWSTR strings[] = {w.c_str()};
        ReportEventW(g_eventSource, level == Level::Warn ? EVENTLOG_WARNING_TYPE : EVENTLOG_ERROR_TYPE, 0,
                     MSG_GENERIC, nullptr, 1, 0, strings, nullptr);
    }
}

void Access(std::string_view l) {
    if (!g_accessEnabled) return;
    std::string line = std::string(l) + "\r\n";
    std::lock_guard lk(g_mu);
    RotateIfNeeded(g_access, L"access");
    WriteLine(g_access, line);
}

} // namespace wsrv::log
