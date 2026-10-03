// Small shared helpers: string conversion, randomness, HTTP dates, misc.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>  // types only (http.h needs SOCKADDR); no ws2_32 dependency
#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wsrv {

constexpr const char* kVersion = "1.0.0";
constexpr const wchar_t* kServiceName = L"wsrv";
constexpr const wchar_t* kAdminHost = L"local.admin";
constexpr int kAdminPort = 8192;

std::string ToUtf8(std::wstring_view w);
std::wstring FromUtf8(std::string_view s);

std::string ToLowerAscii(std::string_view s);
std::wstring ToLowerAscii(std::wstring_view s);
bool EqualsNoCase(std::string_view a, std::string_view b);
bool EqualsNoCase(std::wstring_view a, std::wstring_view b);
bool StartsWithNoCase(std::wstring_view s, std::wstring_view prefix);
std::string_view Trim(std::string_view s);
std::vector<std::string_view> Split(std::string_view s, char sep);

std::string Hex(const uint8_t* data, size_t len);
std::string RandomHex(size_t bytes);
bool ConstantTimeEquals(std::string_view a, std::string_view b);

std::string HtmlEscape(std::string_view s);
// Percent-encodes a UTF-8 path, leaving '/' and RFC 3986 unreserved characters alone.
std::string UrlEncodePath(std::string_view utf8Path);
// Decodes %XX sequences ('+' is left as-is). Returns nullopt on malformed escapes.
std::optional<std::string> UrlDecode(std::string_view s);
// Returns the value of `name` from an application/x-www-form-urlencoded style query (no leading '?').
std::optional<std::string> QueryParam(std::string_view query, std::string_view name);

// HTTP dates (IMF-fixdate, RFC 9110 5.6.7). Seconds since the Unix epoch.
int64_t FileTimeToUnix(const FILETIME& ft);
int64_t NowUnix();
std::string FormatHttpDate(int64_t unixSeconds);
std::optional<int64_t> ParseHttpDate(std::string_view s);

std::wstring ErrorText(DWORD err);
std::string ErrorTextUtf8(DWORD err);

// %ProgramData%\wsrv by default.
std::wstring DefaultDataDir();
std::wstring ExePath();
bool IsElevated();
std::wstring CurrentUserSidString();

// HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters value (e.g. EnableHttp3).
std::optional<DWORD> ReadHttpParameter(const wchar_t* name);

// http.sys reads its feature switches only when the HTTP driver loads (at boot). A switch that is
// on but was written after boot is not active yet.
enum class HttpFeatureState { Disabled, PendingRestart, Enabled };
HttpFeatureState QueryHttpFeature(const wchar_t* name);
const char* HttpFeatureStateName(HttpFeatureState s);  // "disabled" | "pending" | "enabled"

// RAII for kernel handles.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE h) : h_(h) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& o) noexcept : h_(o.release()) {}
    UniqueHandle& operator=(UniqueHandle&& o) noexcept { if (this != &o) { reset(o.release()); } return *this; }
    HANDLE get() const { return h_; }
    bool valid() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
    HANDLE release() { HANDLE h = h_; h_ = nullptr; return h; }
    void reset(HANDLE h = nullptr) { if (valid()) CloseHandle(h_); h_ = h; }
private:
    HANDLE h_ = nullptr;
};

} // namespace wsrv
