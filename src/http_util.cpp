#include "http_util.h"

#include "util.h"

#include <cstdio>

namespace wsrv {

static bool ParseU64(std::string_view s, uint64_t& out) {
    if (s.empty() || s.size() > 19) return false;
    out = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        out = out * 10 + uint64_t(c - '0');
    }
    return true;
}

ByteRange ParseRange(std::string_view header, uint64_t size) {
    ByteRange r;
    header = Trim(header);
    if (header.size() < 6 || !EqualsNoCase(header.substr(0, 6), "bytes=")) return r;
    std::string_view spec = Trim(header.substr(6));
    if (spec.find(',') != std::string_view::npos) return r;  // multi-range: serve full body
    size_t dash = spec.find('-');
    if (dash == std::string_view::npos) return r;
    std::string_view first = Trim(spec.substr(0, dash)), last = Trim(spec.substr(dash + 1));
    uint64_t a = 0, b = 0;
    if (first.empty()) {
        // Suffix range: last N bytes.
        if (!ParseU64(last, b)) return r;
        if (b == 0 || size == 0) { r.kind = ByteRange::Kind::Unsatisfiable; return r; }
        if (b > size) b = size;
        r.kind = ByteRange::Kind::Satisfiable;
        r.start = size - b;
        r.length = b;
        return r;
    }
    if (!ParseU64(first, a)) return r;
    if (last.empty()) {
        b = size ? size - 1 : 0;
    } else {
        if (!ParseU64(last, b) || b < a) return r;
        if (b >= size) b = size ? size - 1 : 0;
    }
    if (a >= size) { r.kind = ByteRange::Kind::Unsatisfiable; return r; }
    r.kind = ByteRange::Kind::Satisfiable;
    r.start = a;
    r.length = b - a + 1;
    return r;
}

std::string MakeEtag(uint64_t size, uint64_t lastWrite, std::string_view suffix) {
    char buf[64];
    snprintf(buf, sizeof buf, "\"%llx-%llx", (unsigned long long)size, (unsigned long long)lastWrite);
    return std::string(buf) + std::string(suffix) + "\"";
}

static std::string_view StripWeak(std::string_view t) {
    t = Trim(t);
    if (t.size() >= 2 && (t[0] == 'W' || t[0] == 'w') && t[1] == '/') t.remove_prefix(2);
    return t;
}

bool IfNoneMatchMatches(std::string_view header, std::string_view etag) {
    header = Trim(header);
    if (header == "*") return true;
    std::string_view mine = StripWeak(etag);
    for (auto tag : Split(header, ',')) {
        if (StripWeak(tag) == mine) return true;
    }
    return false;
}

bool IfRangeAllows(std::string_view header, std::string_view etag, int64_t lastModifiedUnix) {
    header = Trim(header);
    if (header.empty()) return true;
    if (header.front() == '"') return header == etag;  // strong comparison only
    if (header.size() > 2 && header.substr(0, 2) == "W/") return false;
    auto d = ParseHttpDate(header);
    return d && *d == lastModifiedUnix;
}

bool AcceptsEncoding(std::string_view ae, std::string_view coding) {
    for (auto item : Split(ae, ',')) {
        auto parts = Split(item, ';');
        if (!EqualsNoCase(Trim(parts[0]), coding)) continue;
        for (size_t i = 1; i < parts.size(); ++i) {
            auto p = Trim(parts[i]);
            if (p.size() >= 2 && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
                auto q = Trim(p.substr(2));
                bool zero = !q.empty();
                for (char c : q) if (c != '0' && c != '.') zero = false;
                if (zero) return false;
            }
        }
        return true;
    }
    return false;
}

std::string MimeTypeFor(std::string_view ext, const std::map<std::string, std::string>* overrides) {
    std::string e = ToLowerAscii(ext);
    if (overrides) {
        auto it = overrides->find(e);
        if (it != overrides->end()) return it->second;
    }
    struct Entry { const char* ext; const char* type; };
    static const Entry table[] = {
        {"html", "text/html; charset=utf-8"}, {"htm", "text/html; charset=utf-8"},
        {"xhtml", "application/xhtml+xml"}, {"css", "text/css; charset=utf-8"},
        {"js", "text/javascript; charset=utf-8"}, {"mjs", "text/javascript; charset=utf-8"},
        {"json", "application/json"}, {"map", "application/json"},
        {"webmanifest", "application/manifest+json"}, {"txt", "text/plain; charset=utf-8"},
        {"md", "text/markdown; charset=utf-8"}, {"csv", "text/csv; charset=utf-8"},
        {"xml", "application/xml"}, {"rss", "application/rss+xml"}, {"atom", "application/atom+xml"},
        {"yaml", "text/yaml; charset=utf-8"}, {"yml", "text/yaml; charset=utf-8"},
        {"toml", "text/plain; charset=utf-8"}, {"ics", "text/calendar"}, {"vtt", "text/vtt"},
        {"svg", "image/svg+xml"}, {"png", "image/png"}, {"apng", "image/apng"}, {"jpg", "image/jpeg"},
        {"jpeg", "image/jpeg"}, {"gif", "image/gif"}, {"webp", "image/webp"}, {"avif", "image/avif"},
        {"jxl", "image/jxl"}, {"ico", "image/x-icon"}, {"bmp", "image/bmp"}, {"tif", "image/tiff"},
        {"tiff", "image/tiff"}, {"woff", "font/woff"}, {"woff2", "font/woff2"}, {"ttf", "font/ttf"},
        {"otf", "font/otf"}, {"eot", "application/vnd.ms-fontobject"}, {"mp4", "video/mp4"},
        {"m4v", "video/mp4"}, {"webm", "video/webm"}, {"ogv", "video/ogg"}, {"mov", "video/quicktime"},
        {"mkv", "video/x-matroska"}, {"avi", "video/x-msvideo"}, {"mp3", "audio/mpeg"},
        {"m4a", "audio/mp4"}, {"aac", "audio/aac"}, {"oga", "audio/ogg"}, {"ogg", "audio/ogg"},
        {"opus", "audio/opus"}, {"wav", "audio/wav"}, {"flac", "audio/flac"},
        {"pdf", "application/pdf"}, {"zip", "application/zip"}, {"gz", "application/gzip"},
        {"tar", "application/x-tar"}, {"7z", "application/x-7z-compressed"},
        {"wasm", "application/wasm"}, {"glb", "model/gltf-binary"}, {"gltf", "model/gltf+json"},
        {"epub", "application/epub+zip"},
    };
    for (auto& entry : table)
        if (e == entry.ext) return entry.type;
    return "application/octet-stream";
}

bool IsValidAlias(std::string_view host, std::string* error) {
    auto fail = [&](const char* msg) { if (error) *error = msg; return false; };
    if (host.size() < 7 || host.size() > 253) return fail("Alias must be between 7 and 253 characters.");
    if (host.substr(0, 6) != "local.") return fail("Alias must start with \"local.\".");
    if (host == "local.admin") return fail("\"local.admin\" is reserved for the admin site.");
    for (auto label : Split(host, '.')) {
        if (label.empty() || label.size() > 63) return fail("Each part of the alias must be 1-63 characters.");
        if (label.front() == '-' || label.back() == '-') return fail("Alias parts cannot start or end with '-'.");
        for (char c : label) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
            if (!ok) return fail("Alias may only contain lower-case letters, digits, '-' and '.'.");
        }
    }
    return true;
}

const char* ReasonPhrase(int s) {
    switch (s) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 416: return "Range Not Satisfiable";
    case 421: return "Misdirected Request";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "Status";
    }
}

} // namespace wsrv
