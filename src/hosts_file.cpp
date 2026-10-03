#include "hosts_file.h"

#include "log.h"
#include "util.h"

namespace wsrv::hosts {

namespace {

constexpr const char* kBegin = "# BEGIN wsrv (managed by wsrv - do not edit)";
constexpr const char* kEnd = "# END wsrv";

std::wstring HostsPath() {
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    return std::wstring(sys) + L"\\drivers\\etc\\hosts";
}

} // namespace

std::string ApplyBlock(const std::string& original, const std::vector<std::string>& names) {
    // Drop any existing block, line by line, keeping everything else verbatim.
    std::string kept;
    bool inBlock = false;
    size_t pos = 0;
    while (pos < original.size()) {
        size_t eol = original.find('\n', pos);
        size_t next = eol == std::string::npos ? original.size() : eol + 1;
        std::string line = original.substr(pos, next - pos);
        std::string bare = line;
        while (!bare.empty() && (bare.back() == '\n' || bare.back() == '\r')) bare.pop_back();
        if (bare == kBegin) inBlock = true;
        else if (inBlock && bare == kEnd) inBlock = false;
        else if (!inBlock) kept += line;
        pos = next;
    }
    if (names.empty()) return kept;
    if (!kept.empty() && kept.back() != '\n') kept += "\r\n";
    kept += kBegin;
    kept += "\r\n";
    for (auto& n : names) {
        kept += "127.0.0.1 " + n + "\r\n";
        kept += "::1 " + n + "\r\n";
    }
    kept += kEnd;
    kept += "\r\n";
    return kept;
}

bool Update(const std::vector<std::string>& names, std::string* error) {
    std::wstring path = HostsPath();
    std::string original;
    {
        UniqueHandle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (h.valid()) {
            LARGE_INTEGER size{};
            GetFileSizeEx(h.get(), &size);
            if (size.QuadPart > 16 * 1024 * 1024) { if (error) *error = "hosts file is unexpectedly large"; return false; }
            original.resize(size_t(size.QuadPart));
            DWORD n = 0;
            if (!original.empty() && !ReadFile(h.get(), original.data(), (DWORD)original.size(), &n, nullptr)) {
                if (error) *error = "read hosts: " + ErrorTextUtf8(GetLastError());
                return false;
            }
            original.resize(n);
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            if (error) *error = "open hosts: " + ErrorTextUtf8(GetLastError());
            return false;
        }
    }
    std::string updated = ApplyBlock(original, names);
    if (updated == original) return true;

    std::wstring tmp = path + L".wsrv.tmp";
    {
        UniqueHandle h(CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h.valid()) { if (error) *error = "write hosts: " + ErrorTextUtf8(GetLastError()); return false; }
        DWORD n = 0;
        if (!WriteFile(h.get(), updated.data(), (DWORD)updated.size(), &n, nullptr) || n != updated.size() ||
            !FlushFileBuffers(h.get())) {
            if (error) *error = "write hosts: " + ErrorTextUtf8(GetLastError());
            DeleteFileW(tmp.c_str());
            return false;
        }
    }
    // ReplaceFile keeps the original file's ACL and attributes.
    BOOL ok = GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES
                  ? ReplaceFileW(path.c_str(), tmp.c_str(), nullptr, REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)
                  : MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
    if (!ok) {
        if (error) *error = "replace hosts: " + ErrorTextUtf8(GetLastError());
        DeleteFileW(tmp.c_str());
        return false;
    }
    log::Info("Updated hosts file (" + std::to_string(names.size()) + " wsrv aliases)");
    return true;
}

} // namespace wsrv::hosts
