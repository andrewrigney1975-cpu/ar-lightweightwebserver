#include "util.h"

#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

#include <cstdio>

namespace wsrv {

std::string ToUtf8(std::wstring_view w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring FromUtf8(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string ToLowerAscii(std::string_view s) {
    std::string out(s);
    for (auto& c : out) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return out;
}

std::wstring ToLowerAscii(std::wstring_view s) {
    std::wstring out(s);
    for (auto& c : out) if (c >= L'A' && c <= L'Z') c = wchar_t(c - L'A' + L'a');
    return out;
}

bool EqualsNoCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = char(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = char(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

bool EqualsNoCase(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    return CompareStringOrdinal(a.data(), (int)a.size(), b.data(), (int)b.size(), TRUE) == CSTR_EQUAL;
}

bool StartsWithNoCase(std::wstring_view s, std::wstring_view prefix) {
    return s.size() >= prefix.size() && EqualsNoCase(s.substr(0, prefix.size()), prefix);
}

std::string_view Trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

std::vector<std::string_view> Split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    size_t start = 0;
    for (;;) {
        size_t pos = s.find(sep, start);
        if (pos == std::string_view::npos) { out.push_back(s.substr(start)); break; }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

std::string Hex(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 15];
    }
    return out;
}

std::string RandomHex(size_t bytes) {
    std::vector<uint8_t> buf(bytes);
    BCryptGenRandom(nullptr, buf.data(), (ULONG)buf.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return Hex(buf.data(), buf.size());
}

bool ConstantTimeEquals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

std::string HtmlEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

std::string UrlEncodePath(std::string_view s) {
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        bool keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '-' || c == '.' || c == '_' || c == '~' || c == '/';
        if (keep) out += char(c);
        else { out += '%'; out += digits[c >> 4]; out += digits[c & 15]; }
    }
    return out;
}

static int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<std::string> UrlDecode(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%') {
            if (i + 2 >= s.size()) return std::nullopt;
            int hi = HexVal(s[i + 1]), lo = HexVal(s[i + 2]);
            if (hi < 0 || lo < 0) return std::nullopt;
            out += char(hi * 16 + lo);
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

std::optional<std::string> QueryParam(std::string_view query, std::string_view name) {
    if (!query.empty() && query.front() == '?') query.remove_prefix(1);
    for (auto part : Split(query, '&')) {
        size_t eq = part.find('=');
        std::string_view key = part.substr(0, eq);
        if (key != name) continue;
        std::string raw(eq == std::string_view::npos ? std::string_view{} : part.substr(eq + 1));
        for (auto& c : raw) if (c == '+') c = ' ';
        return UrlDecode(raw);
    }
    return std::nullopt;
}

// FILETIME epoch (1601) to Unix epoch (1970) in 100ns ticks.
static constexpr int64_t kEpochDelta = 116444736000000000LL;

int64_t FileTimeToUnix(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (int64_t(u.QuadPart) - kEpochDelta) / 10000000LL;
}

int64_t NowUnix() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return FileTimeToUnix(ft);
}

static const char* kDays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

std::string FormatHttpDate(int64_t t) {
    ULARGE_INTEGER u;
    u.QuadPart = uint64_t(t * 10000000LL + kEpochDelta);
    FILETIME ft{u.LowPart, u.HighPart};
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[40];
    snprintf(buf, sizeof buf, "%s, %02u %s %04u %02u:%02u:%02u GMT", kDays[st.wDayOfWeek], st.wDay,
             kMonths[st.wMonth - 1], st.wYear, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::optional<int64_t> ParseHttpDate(std::string_view s) {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    s = Trim(s);
    if (s.size() != 29 || s[3] != ',' || s[4] != ' ' || s.substr(26) != "GMT") return std::nullopt;
    auto num = [&](size_t pos, size_t len) -> int {
        int v = 0;
        for (size_t i = pos; i < pos + len; ++i) {
            if (s[i] < '0' || s[i] > '9') return -1;
            v = v * 10 + (s[i] - '0');
        }
        return v;
    };
    SYSTEMTIME st{};
    int day = num(5, 2), year = num(12, 4), hh = num(17, 2), mm = num(20, 2), ss = num(23, 2);
    if (day < 1 || year < 1601 || hh < 0 || mm < 0 || ss < 0 || s[19] != ':' || s[22] != ':') return std::nullopt;
    int month = -1;
    for (int i = 0; i < 12; ++i) if (s.substr(8, 3) == kMonths[i]) month = i + 1;
    if (month < 0) return std::nullopt;
    st.wYear = WORD(year); st.wMonth = WORD(month); st.wDay = WORD(day);
    st.wHour = WORD(hh); st.wMinute = WORD(mm); st.wSecond = WORD(ss);
    FILETIME ft;
    if (!SystemTimeToFileTime(&st, &ft)) return std::nullopt;
    return FileTimeToUnix(ft);
}

std::wstring ErrorText(DWORD err) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring out = n ? std::wstring(buf, n) : L"error";
    if (buf) LocalFree(buf);
    while (!out.empty() && (out.back() == L'\n' || out.back() == L'\r' || out.back() == L'.')) out.pop_back();
    return out + L" (" + std::to_wstring(err) + L")";
}

std::string ErrorTextUtf8(DWORD err) { return ToUtf8(ErrorText(err)); }

std::wstring DefaultDataDir() {
    PWSTR p = nullptr;
    std::wstring out = L"C:\\ProgramData";
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &p))) out = p;
    CoTaskMemFree(p);
    return out + L"\\wsrv";
}

std::wstring ExePath() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
        if (n < buf.size()) { buf.resize(n); return buf; }
        buf.resize(buf.size() * 2);
    }
}

bool IsElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e{};
    DWORD n = 0;
    bool ok = GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n) && e.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

std::wstring CurrentUserSidString() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return {};
    std::vector<BYTE> buf(256);
    DWORD n = 0;
    std::wstring out;
    if (GetTokenInformation(tok, TokenUser, buf.data(), (DWORD)buf.size(), &n)) {
        auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &s)) { out = s; LocalFree(s); }
    }
    CloseHandle(tok);
    return out;
}

std::optional<DWORD> ReadHttpParameter(const wchar_t* name) {
    DWORD v = 0, size = sizeof v;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters", name,
                     RRF_RT_REG_DWORD, nullptr, &v, &size) != ERROR_SUCCESS)
        return std::nullopt;
    return v;
}

HttpFeatureState QueryHttpFeature(const wchar_t* name) {
    if (!ReadHttpParameter(name).value_or(0)) return HttpFeatureState::Disabled;
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters", 0, KEY_QUERY_VALUE,
                      &key) != ERROR_SUCCESS)
        return HttpFeatureState::Enabled;
    FILETIME lastWrite{};
    LSTATUS r = RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                 nullptr, &lastWrite);
    RegCloseKey(key);
    if (r != ERROR_SUCCESS) return HttpFeatureState::Enabled;

    // Boot time = now - uptime. The key's timestamp covers every value under it, so a change to an
    // unrelated http.sys setting since boot also reads as "pending" — the conservative answer.
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER n{{now.dwLowDateTime, now.dwHighDateTime}}, w{{lastWrite.dwLowDateTime, lastWrite.dwHighDateTime}};
    ULONGLONG boot = n.QuadPart - GetTickCount64() * 10000ull;
    return w.QuadPart > boot ? HttpFeatureState::PendingRestart : HttpFeatureState::Enabled;
}

const char* HttpFeatureStateName(HttpFeatureState s) {
    switch (s) {
    case HttpFeatureState::Enabled: return "enabled";
    case HttpFeatureState::PendingRestart: return "pending";
    default: return "disabled";
    }
}

} // namespace wsrv
