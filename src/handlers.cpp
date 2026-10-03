#include "handlers.h"

#include "http_util.h"
#include "log.h"

#include <algorithm>
#include <cstdio>

namespace wsrv {

namespace {

constexpr const char* kHsts = "max-age=31536000";

void CommonHeaders(Response& resp) {
    resp.set("X-Content-Type-Options", "nosniff");
    resp.set("Strict-Transport-Security", kHsts);
}

int StatusFor(GuardResult r) {
    switch (r) {
    case GuardResult::BadRequest: return 400;
    case GuardResult::Forbidden: return 403;
    case GuardResult::Unavailable: return 503;
    default: return 404;
    }
}

std::wstring Extension(const std::wstring& path) {
    size_t slash = path.find_last_of(L'\\');
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || (slash != std::wstring::npos && dot < slash)) return {};
    return path.substr(dot + 1);
}

std::string FormatSize(uint64_t n) {
    char buf[32];
    if (n < 1024) snprintf(buf, sizeof buf, "%llu B", (unsigned long long)n);
    else if (n < 1024 * 1024) snprintf(buf, sizeof buf, "%.1f KB", n / 1024.0);
    else if (n < 1024ull * 1024 * 1024) snprintf(buf, sizeof buf, "%.1f MB", n / (1024.0 * 1024));
    else snprintf(buf, sizeof buf, "%.1f GB", n / (1024.0 * 1024 * 1024));
    return buf;
}

void ServeListing(const SiteRuntime& site, const ContainedFile& dir, std::wstring_view urlPath, Response& resp) {
    struct Entry { std::wstring name; bool isDir; uint64_t size; int64_t mtime; };
    std::vector<Entry> entries;
    WIN32_FIND_DATAW fd;
    std::wstring pattern = dir.finalPath + L"\\*";
    HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            std::wstring_view name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            if (!site.policy.serveHidden &&
                (name.front() == L'.' || (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))))
                continue;
            if (IsForbiddenSegment(name)) continue;
            entries.push_back({std::wstring(name), (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
                               (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow, FileTimeToUnix(fd.ftLastWriteTime)});
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        if (a.isDir != b.isDir) return a.isDir;
        return CompareStringOrdinal(a.name.c_str(), -1, b.name.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    });

    std::string title = HtmlEscape(ToUtf8(urlPath));
    std::string html =
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Index of " + title + "</title>"
        "<style>:root{color-scheme:light dark}body{font:15px/1.5 system-ui,sans-serif;margin:0 auto;padding:24px 16px;max-width:900px}"
        "h1{font-size:18px;font-weight:600;word-break:break-all}table{width:100%;border-collapse:collapse}"
        "td{padding:4px 8px;border-bottom:1px solid #8883}td.n{word-break:break-all}td.s,td.d{white-space:nowrap;color:#888}"
        "td.s{text-align:right}a{text-decoration:none}a:hover{text-decoration:underline}</style></head><body>"
        "<h1>Index of " + title + "</h1><table>";
    if (urlPath != L"/") html += "<tr><td class=n><a href=\"../\">../</a></td><td class=s></td><td class=d></td></tr>";
    for (auto& e : entries) {
        std::string name = ToUtf8(e.name);
        std::string href = UrlEncodePath(name) + (e.isDir ? "/" : "");
        html += "<tr><td class=n><a href=\"" + HtmlEscape(href) + "\">" + HtmlEscape(name) + (e.isDir ? "/" : "") +
                "</a></td><td class=s>" + (e.isDir ? "" : FormatSize(e.size)) + "</td><td class=d>" +
                FormatHttpDate(e.mtime) + "</td></tr>";
    }
    html += "</table></body></html>";
    resp.status = 200;
    resp.body = std::move(html);
    resp.set("Content-Type", "text/html; charset=utf-8");
    resp.set("Cache-Control", "no-cache");
}

void ServeFile(const SiteRuntime& site, const std::map<std::string, std::string>& mime, Request& req, Response& resp,
               ContainedFile& file, const std::wstring& rel) {
    std::string contentType = MimeTypeFor(ToUtf8(Extension(file.finalPath)), &mime);

    // Prefer a pre-compressed sibling (file.br / file.gz) when the client accepts it.
    std::string encoding;
    bool hasVariant = false;
    std::string ae = req.header(HttpHeaderAcceptEncoding);
    for (const char* coding : {"br", "gzip"}) {
        std::wstring suffix = coding[0] == 'b' ? L".br" : L".gz";
        ContainedFile variant;
        if (OpenContained(site.policy, rel + suffix, variant) != GuardResult::Ok || variant.isDirectory()) continue;
        hasVariant = true;
        if (encoding.empty() && AcceptsEncoding(ae, coding)) {
            encoding = coding;
            file = std::move(variant);
        }
    }

    std::string etag = MakeEtag(file.size(), file.lastWrite(), encoding.empty() ? "" : "-" + encoding);
    int64_t lastMod = FileTimeToUnix(file.info.ftLastWriteTime);
    uint64_t size = file.size();

    resp.set("Content-Type", contentType);
    resp.set("ETag", etag);
    resp.set("Last-Modified", FormatHttpDate(lastMod));
    resp.set("Cache-Control", site.site.cacheControl.empty() ? "no-cache" : site.site.cacheControl);
    resp.set("Accept-Ranges", "bytes");
    if (!encoding.empty()) resp.set("Content-Encoding", encoding);
    if (hasVariant) resp.set("Vary", "Accept-Encoding");

    // Conditional GET.
    std::string inm = req.header(HttpHeaderIfNoneMatch);
    bool notModified = false;
    if (!inm.empty()) {
        notModified = IfNoneMatchMatches(inm, etag);
    } else {
        std::string ims = req.header(HttpHeaderIfModifiedSince);
        if (auto t = ParseHttpDate(ims)) notModified = lastMod <= *t;
    }
    if (notModified) {
        resp.status = 304;
        return;
    }

    resp.status = 200;
    resp.fileOffset = 0;
    resp.fileLength = size;
    std::string range = req.header(HttpHeaderRange);
    if (!range.empty() && IfRangeAllows(req.header(HttpHeaderIfRange), etag, lastMod)) {
        ByteRange br = ParseRange(range, size);
        if (br.kind == ByteRange::Kind::Unsatisfiable) {
            resp.status = 416;
            resp.set("Content-Range", "bytes */" + std::to_string(size));
            resp.headers.erase(std::remove_if(resp.headers.begin(), resp.headers.end(),
                                              [](auto& h) { return EqualsNoCase(h.first, "Content-Encoding"); }),
                               resp.headers.end());
            return;
        }
        if (br.kind == ByteRange::Kind::Satisfiable) {
            resp.status = 206;
            resp.fileOffset = br.start;
            resp.fileLength = br.length;
            resp.set("Content-Range", "bytes " + std::to_string(br.start) + "-" + std::to_string(br.start + br.length - 1) +
                                          "/" + std::to_string(size));
        }
    }
    resp.file = std::move(file.handle);
}

} // namespace

void SetErrorPage(Response& resp, int status) {
    resp.status = status;
    resp.file.reset();
    std::string code = std::to_string(status) + " " + ReasonPhrase(status);
    resp.body = "<!doctype html><html lang=en><head><meta charset=utf-8><title>" + code +
                "</title><style>:root{color-scheme:light dark}body{font:16px system-ui,sans-serif;display:grid;"
                "place-items:center;min-height:100vh;margin:0}</style></head><body><p>" + code + "</p></body></html>";
    resp.set("Content-Type", "text/html; charset=utf-8");
    resp.set("Cache-Control", "no-store");
}

bool AllowReadOnly(Request& req, Response& resp) {
    resp.sendBody = req.verb() != HttpVerbHEAD;
    if (req.verb() == HttpVerbGET || req.verb() == HttpVerbHEAD) return true;
    SetErrorPage(resp, 405);
    resp.set("Allow", "GET, HEAD");
    CommonHeaders(resp);
    return false;
}

void ServeHello(Request& req, Response& resp) {
    if (!AllowReadOnly(req, resp)) return;
    CommonHeaders(resp);
    if (req.path() != L"/") { SetErrorPage(resp, 404); return; }
    resp.status = 200;
    resp.body =
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Hello, world!</title>"
        "<style>html,body{height:100%;margin:0}body{background:#000;color:#fff;display:flex;align-items:center;"
        "justify-content:center;font:600 clamp(2rem,6vw,4rem)/1.2 system-ui,-apple-system,'Segoe UI',sans-serif;"
        "text-align:center;padding:0 16px}</style></head><body>Hello, world!</body></html>";
    resp.set("Content-Type", "text/html; charset=utf-8");
    resp.set("Cache-Control", "no-cache");
}

void ServeStatic(const SiteRuntime& site, const std::map<std::string, std::string>& mime, Request& req, Response& resp) {
    if (!AllowReadOnly(req, resp)) return;
    CommonHeaders(resp);
    if (!site.rootError.empty() || site.policy.rootFinal.empty()) { SetErrorPage(resp, 503); return; }

    std::wstring rel;
    bool slash = false;
    GuardResult g = SanitizeUrlPath(req.path(), rel, slash);
    if (g != GuardResult::Ok) { SetErrorPage(resp, StatusFor(g)); return; }

    ContainedFile target;
    g = OpenContained(site.policy, rel, target);
    if (g != GuardResult::Ok) { SetErrorPage(resp, StatusFor(g)); return; }

    if (target.isDirectory()) {
        if (!slash && !rel.empty()) {
            resp.status = 301;
            resp.set("Location", UrlEncodePath(ToUtf8(req.path())) + "/" + ToUtf8(req.query()));
            resp.set("Cache-Control", "no-cache");
            return;
        }
        for (const wchar_t* index : {L"index.html", L"index.htm"}) {
            std::wstring indexRel = rel.empty() ? std::wstring(index) : rel + L"\\" + index;
            ContainedFile idx;
            if (OpenContained(site.policy, indexRel, idx) == GuardResult::Ok && !idx.isDirectory()) {
                ServeFile(site, mime, req, resp, idx, indexRel);
                return;
            }
        }
        if (site.site.dirListing) { ServeListing(site, target, req.path(), resp); return; }
        SetErrorPage(resp, 404);
        return;
    }
    if (slash) { SetErrorPage(resp, 404); return; }  // "/file.html/" is not a directory
    ServeFile(site, mime, req, resp, target, rel);
}

} // namespace wsrv
