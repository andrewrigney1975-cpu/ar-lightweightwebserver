// Pure HTTP helpers (no I/O) — ranges, entity tags, conditional requests, MIME types, host names.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace wsrv {

struct ByteRange {
    enum class Kind { None, Satisfiable, Unsatisfiable } kind = Kind::None;
    uint64_t start = 0;
    uint64_t length = 0;
};

// Parses a single-range "bytes=" header against a representation of `size` bytes.
// Multi-range or malformed headers yield Kind::None (serve the full representation).
ByteRange ParseRange(std::string_view header, uint64_t size);

// Strong entity tag for a file version, e.g. "\"1a2b-1d9c3e4f5a6b7c8\"".
std::string MakeEtag(uint64_t size, uint64_t lastWriteFileTime, std::string_view suffix = {});

// If-None-Match evaluation (weak comparison, RFC 9110 13.1.2).
bool IfNoneMatchMatches(std::string_view header, std::string_view etag);
// If-Range evaluation: true when the range may be applied.
bool IfRangeAllows(std::string_view header, std::string_view etag, int64_t lastModifiedUnix);

// Accept-Encoding contains `coding` with non-zero q.
bool AcceptsEncoding(std::string_view acceptEncoding, std::string_view coding);

// MIME type for a file extension (without dot, any case). Overrides take precedence.
std::string MimeTypeFor(std::string_view extension, const std::map<std::string, std::string>* overrides = nullptr);

// "local.foo" style alias: lower-case, starts with "local.", DNS-label rules, not reserved.
bool IsValidAlias(std::string_view host, std::string* error = nullptr);

const char* ReasonPhrase(int status);

} // namespace wsrv
