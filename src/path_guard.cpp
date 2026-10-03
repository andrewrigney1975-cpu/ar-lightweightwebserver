#include "path_guard.h"

#include "log.h"

namespace wsrv {

namespace {

constexpr size_t kMaxSegment = 255;
constexpr size_t kMaxRelPath = 4096;

bool IsDeviceName(std::wstring_view seg) {
    // The device check applies to the part before the first dot, ignoring trailing spaces ("CON .txt").
    std::wstring_view base = seg.substr(0, seg.find(L'.'));
    while (!base.empty() && base.back() == L' ') base.remove_suffix(1);
    std::wstring b = ToLowerAscii(base);
    static const wchar_t* fixed[] = {L"con", L"prn", L"aux", L"nul", L"conin$", L"conout$", L"clock$"};
    for (auto f : fixed) if (b == f) return true;
    if (b.size() == 4 && (b.rfind(L"com", 0) == 0 || b.rfind(L"lpt", 0) == 0)) {
        wchar_t d = b[3];
        // COM0-9, LPT0-9 and the superscript digits Windows also treats as devices.
        if ((d >= L'0' && d <= L'9') || d == L'\u00b9' || d == L'\u00b2' || d == L'\u00b3') return true;
    }
    return false;
}

bool HasDotComponent(std::wstring_view rel) {
    size_t start = 0;
    while (start <= rel.size()) {
        size_t end = rel.find(L'\\', start);
        if (end == std::wstring_view::npos) end = rel.size();
        if (end > start && rel[start] == L'.') return true;
        start = end + 1;
    }
    return false;
}

GuardResult FromWin32(DWORD err) {
    switch (err) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
    case ERROR_DIRECTORY:
    case ERROR_NOT_READY:
    case ERROR_CANT_ACCESS_FILE:
    case ERROR_CANT_RESOLVE_FILENAME:
        return GuardResult::NotFound;
    case ERROR_ACCESS_DENIED:
        return GuardResult::Forbidden;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        return GuardResult::Unavailable;
    default:
        return GuardResult::NotFound;
    }
}

std::wstring FinalPathOf(HANDLE h, DWORD* err) {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetFinalPathNameByHandleW(h, buf.data(), (DWORD)buf.size(), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (n == 0) { if (err) *err = GetLastError(); return {}; }
        if (n < buf.size()) { buf.resize(n); return buf; }
        buf.resize(n + 1);
    }
}

} // namespace

bool IsForbiddenSegment(std::wstring_view seg) {
    if (seg.empty() || seg.size() > kMaxSegment) return true;
    if (seg == L"." || seg == L"..") return true;
    for (wchar_t c : seg) {
        if (c < 0x20 || c == 0x7F) return true;
        switch (c) {
        case L'\\': case L'/': case L':': case L'*': case L'?': case L'"': case L'<': case L'>': case L'|':
            return true;
        default: break;
        }
    }
    // Win32 silently strips trailing dots and spaces, which would alias other names.
    if (seg.back() == L'.' || seg.back() == L' ') return true;
    return IsDeviceName(seg);
}

GuardResult SanitizeUrlPath(std::wstring_view urlPath, std::wstring& relOut, bool& endsWithSlash) {
    relOut.clear();
    endsWithSlash = false;
    if (urlPath.empty() || urlPath.front() != L'/') return GuardResult::BadRequest;
    endsWithSlash = urlPath.back() == L'/';
    size_t start = 1;
    while (start <= urlPath.size()) {
        size_t end = urlPath.find(L'/', start);
        if (end == std::wstring_view::npos) end = urlPath.size();
        std::wstring_view seg = urlPath.substr(start, end - start);
        if (!seg.empty()) {  // collapse "//"
            if (seg.find(L'\\') != std::wstring_view::npos || seg.find(L'\0') != std::wstring_view::npos)
                return GuardResult::BadRequest;
            if (IsForbiddenSegment(seg)) return seg == L"." || seg == L".." ? GuardResult::BadRequest : GuardResult::NotFound;
            if (!relOut.empty()) relOut += L'\\';
            relOut += seg;
            if (relOut.size() > kMaxRelPath) return GuardResult::BadRequest;
        }
        start = end + 1;
    }
    return GuardResult::Ok;
}

std::wstring FinalPathOfDirectory(const std::wstring& path, DWORD* err) {
    UniqueHandle h(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!h.valid()) { if (err) *err = GetLastError(); return {}; }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h.get(), &info) || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        if (err) *err = ERROR_DIRECTORY;
        return {};
    }
    std::wstring p = FinalPathOf(h.get(), err);
    while (p.size() > 7 && p.back() == L'\\') p.pop_back();  // keep "\\?\C:\" intact
    return p;
}

bool IsWithin(std::wstring_view root, std::wstring_view cand) {
    if (root.empty()) return false;
    while (root.size() > 1 && root.back() == L'\\') root.remove_suffix(1);
    if (cand.size() < root.size()) return false;
    if (!EqualsNoCase(cand.substr(0, root.size()), root)) return false;
    if (cand.size() == root.size()) return true;
    return cand[root.size()] == L'\\' || root.back() == L'\\';
}

GuardResult OpenContained(const GuardPolicy& policy, const std::wstring& rel, ContainedFile& out) {
    if (policy.rootFinal.empty()) return GuardResult::Unavailable;
    if (rel.size() > kMaxRelPath) return GuardResult::BadRequest;
    if (!policy.serveHidden && HasDotComponent(rel)) return GuardResult::NotFound;

    // rootFinal already has the \\?\ prefix, which disables all further Win32 path rewriting.
    std::wstring full = policy.rootFinal;
    if (!rel.empty()) { if (full.back() != L'\\') full += L'\\'; full += rel; }

    out.handle.reset(CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!out.handle.valid()) return FromWin32(GetLastError());
    if (!GetFileInformationByHandle(out.handle.get(), &out.info)) { out.handle.reset(); return GuardResult::NotFound; }

    DWORD err = 0;
    out.finalPath = FinalPathOf(out.handle.get(), &err);
    if (out.finalPath.empty() || !IsWithin(policy.rootFinal, out.finalPath)) {
        log::Warn("Blocked access outside web root: " + ToUtf8(full) + " -> " + ToUtf8(out.finalPath));
        out.handle.reset();
        return GuardResult::NotFound;
    }
    if (!policy.forbiddenFinal.empty() && IsWithin(policy.forbiddenFinal, out.finalPath)) {
        log::Warn("Blocked access to wsrv data directory: " + ToUtf8(out.finalPath));
        out.handle.reset();
        return GuardResult::NotFound;
    }
    if (!policy.serveHidden) {
        // Re-check on the resolved name: an 8.3 alias like "ENV~1" may point at ".env".
        std::wstring_view relFinal = std::wstring_view(out.finalPath).substr(policy.rootFinal.size());
        bool hidden = (out.info.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0 &&
                      !relFinal.empty();
        if (hidden || HasDotComponent(relFinal)) { out.handle.reset(); return GuardResult::NotFound; }
    }
    return GuardResult::Ok;
}

} // namespace wsrv
