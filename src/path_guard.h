// Keeps every file access inside a site's web root.
//
// Two layers:
//  1. SanitizeUrlPath rejects anything that is not a plain sequence of ordinary file-name segments.
//  2. OpenContained opens the target and checks the *final* on-disk path (after junctions, symlinks,
//     8.3 short names and case folding) is still at or below the root's final path.
#pragma once

#include "util.h"

#include <string>
#include <string_view>

namespace wsrv {

enum class GuardResult { Ok, BadRequest, NotFound, Forbidden, Unavailable };

// urlPath: decoded absolute path from the request ("/a/b.html").
// relOut:  relative Windows path ("a\\b.html"), empty for the root itself.
// endsWithSlash: whether the URL path ended in '/'.
GuardResult SanitizeUrlPath(std::wstring_view urlPath, std::wstring& relOut, bool& endsWithSlash);

// True for a file-name segment that must never be served (device names, trailing dot/space, etc.).
bool IsForbiddenSegment(std::wstring_view segment);

// Final ("\\?\X:\...") path of an existing directory, or empty with *err set.
std::wstring FinalPathOfDirectory(const std::wstring& path, DWORD* err = nullptr);

// Case-insensitive "candidate == root || candidate starts with root + '\'".
bool IsWithin(std::wstring_view rootFinal, std::wstring_view candidateFinal);

struct ContainedFile {
    UniqueHandle handle;
    BY_HANDLE_FILE_INFORMATION info{};
    std::wstring finalPath;
    bool isDirectory() const { return (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0; }
    uint64_t size() const { return (uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow; }
    uint64_t lastWrite() const {
        return (uint64_t(info.ftLastWriteTime.dwHighDateTime) << 32) | info.ftLastWriteTime.dwLowDateTime;
    }
};

struct GuardPolicy {
    std::wstring rootFinal;      // from FinalPathOfDirectory
    std::wstring forbiddenFinal; // a directory that must never be reachable (wsrv data dir); may be empty
    bool serveHidden = false;    // dot-files and hidden/system files
};

// rel must come from SanitizeUrlPath (or be a further sanitized child like rel + L"\\index.html").
GuardResult OpenContained(const GuardPolicy& policy, const std::wstring& rel, ContainedFile& out);

} // namespace wsrv
