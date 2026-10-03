#include "admin.h"

#include "handlers.h"
#include "http_util.h"
#include "log.h"
#include "path_guard.h"
#include "resource.h"

#include <algorithm>

namespace wsrv {

namespace {

constexpr const char* kCookie = "wsrv_session";
constexpr int64_t kSessionSeconds = 12 * 3600;
constexpr size_t kMaxBody = 64 * 1024;

std::string AdminOrigin() { return "https://" + ToUtf8(kAdminHost) + ":" + std::to_string(kAdminPort); }

void SecurityHeaders(Response& resp) {
    resp.set("Content-Security-Policy",
             "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
             "frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    resp.set("X-Frame-Options", "DENY");
    resp.set("Referrer-Policy", "no-referrer");
    resp.set("X-Content-Type-Options", "nosniff");
    resp.set("Strict-Transport-Security", "max-age=31536000");
    resp.set("Cross-Origin-Opener-Policy", "same-origin");
    resp.set("Cross-Origin-Resource-Policy", "same-origin");
}

void Json(Response& resp, int status, const json::Value& v) {
    resp.status = status;
    resp.body = v.dump();
    resp.set("Content-Type", "application/json; charset=utf-8");
    resp.set("Cache-Control", "no-store");
}

void JsonError(Response& resp, int status, const std::string& message) {
    json::Value v = json::Value::Object();
    v.set("error", json::Value::String(message));
    Json(resp, status, v);
}

std::string CookieValue(const std::string& header, std::string_view name) {
    for (auto part : Split(header, ';')) {
        part = Trim(part);
        size_t eq = part.find('=');
        if (eq != std::string_view::npos && part.substr(0, eq) == name) return std::string(part.substr(eq + 1));
    }
    return {};
}

bool IsDrivePath(std::wstring_view p) {
    return p.size() >= 3 && ((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) && p[1] == L':' &&
           p[2] == L'\\';
}

std::optional<int64_t> ParseId(std::wstring_view s) {
    if (s.empty() || s.size() > 18) return std::nullopt;
    int64_t v = 0;
    for (wchar_t c : s) {
        if (c < L'0' || c > L'9') return std::nullopt;
        v = v * 10 + (c - L'0');
    }
    return v;
}

std::string EdgeCommand(const std::vector<Site>& sites) {
    std::string origins, first;
    for (auto& s : sites) {
        if (!s.enabled) continue;
        if (!origins.empty()) origins += ",";
        origins += s.host + ":" + std::to_string(s.port);
        if (first.empty()) first = "https://" + s.host + (s.port == 443 ? "" : ":" + std::to_string(s.port)) + "/";
    }
    if (!origins.empty()) origins += ",";
    origins += ToUtf8(kAdminHost) + ":" + std::to_string(kAdminPort);
    if (first.empty()) first = AdminOrigin() + "/";
    return "start msedge --user-data-dir=\"%TEMP%\\wsrv-edge-h3\" --origin-to-force-quic-on=" + origins + " " + first;
}

} // namespace

Admin::Admin(ConfigStore& store, Reconciler& recon, std::wstring dataDirFinal)
    : store_(store), recon_(recon), dataDirFinal_(std::move(dataDirFinal)) {}

std::string Admin::LoginUrl(const std::string& token) { return AdminOrigin() + "/login?t=" + token; }

std::string Admin::IssueLoginToken(int64_t ttl) {
    std::string t = RandomHex(32);
    std::lock_guard lk(mu_);
    int64_t now = NowUnix();
    for (auto it = tokens_.begin(); it != tokens_.end();) it = it->second < now ? tokens_.erase(it) : std::next(it);
    tokens_[t] = now + ttl;
    return t;
}

std::string Admin::NewSession() {
    std::string s = RandomHex(32);
    std::lock_guard lk(mu_);
    int64_t now = NowUnix();
    for (auto it = sessions_.begin(); it != sessions_.end();) it = it->second < now ? sessions_.erase(it) : std::next(it);
    sessions_[s] = now + kSessionSeconds;
    return s;
}

bool Admin::Authenticated(Request& req) {
    std::string sid = CookieValue(req.header(HttpHeaderCookie), kCookie);
    if (sid.empty()) return false;
    std::lock_guard lk(mu_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) return false;
    int64_t now = NowUnix();
    if (it->second < now) { sessions_.erase(it); return false; }
    it->second = now + kSessionSeconds;  // sliding expiry
    return true;
}

void Admin::ServeResource(Response& resp, int id, const char* contentType) {
    HRSRC r = FindResourceW(nullptr, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(10) /* RT_RCDATA */);
    HGLOBAL g = r ? LoadResource(nullptr, r) : nullptr;
    const char* data = g ? static_cast<const char*>(LockResource(g)) : nullptr;
    if (!data) { SetErrorPage(resp, 404); return; }
    resp.status = 200;
    resp.body.assign(data, SizeofResource(nullptr, r));
    resp.set("Content-Type", contentType);
    resp.set("Cache-Control", "no-cache");
}

void Admin::Handle(Request& req, Response& resp) {
    SecurityHeaders(resp);
    resp.sendBody = req.verb() != HttpVerbHEAD;

    // Anti DNS-rebinding: only the exact admin authority is accepted.
    std::wstring expectedHost = std::wstring(kAdminHost) + L":" + std::to_wstring(kAdminPort);
    if (!EqualsNoCase(req.host(), expectedHost)) { SetErrorPage(resp, 421); return; }

    std::wstring_view path = req.path();
    if (path.substr(0, 5) == L"/api/") { HandleApi(req, resp, path.substr(4)); return; }

    bool readOnly = req.verb() == HttpVerbGET || req.verb() == HttpVerbHEAD;
    if (!readOnly) { SetErrorPage(resp, 405); resp.set("Allow", "GET, HEAD"); return; }

    if (path == L"/login") {
        std::string token = QueryParam(ToUtf8(req.query()), "t").value_or("");
        bool ok = false;
        {
            std::lock_guard lk(mu_);
            for (auto it = tokens_.begin(); it != tokens_.end(); ++it) {
                if (ConstantTimeEquals(it->first, token)) {
                    ok = it->second >= NowUnix();
                    tokens_.erase(it);  // one-time
                    break;
                }
            }
        }
        if (!ok) {
            resp.status = 403;
            resp.body = "<!doctype html><meta charset=utf-8><title>Sign-in link expired</title>"
                        "<p style=\"font:16px system-ui;margin:40px\">This sign-in link has expired or was already used. "
                        "Open <b>wsrv Admin</b> from the Start menu (or run <code>wsrv open-admin</code>) again.</p>";
            resp.set("Content-Type", "text/html; charset=utf-8");
            resp.set("Cache-Control", "no-store");
            return;
        }
        std::string sid = NewSession();
        resp.status = 303;
        resp.set("Location", "/");
        resp.set("Set-Cookie", std::string(kCookie) + "=" + sid + "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=" +
                                   std::to_string(kSessionSeconds));
        resp.set("Cache-Control", "no-store");
        log::Info("Admin signed in");
        return;
    }
    if (path == L"/" || path == L"/index.html") return ServeResource(resp, IDR_ADMIN_HTML, "text/html; charset=utf-8");
    if (path == L"/app.js") return ServeResource(resp, IDR_ADMIN_JS, "text/javascript; charset=utf-8");
    if (path == L"/app.css") return ServeResource(resp, IDR_ADMIN_CSS, "text/css; charset=utf-8");
    if (path == L"/favicon.svg") return ServeResource(resp, IDR_ADMIN_ICON, "image/svg+xml");
    SetErrorPage(resp, 404);
}

void Admin::HandleApi(Request& req, Response& resp, std::wstring_view path) {
    if (!Authenticated(req)) { JsonError(resp, 401, "Not signed in."); return; }

    HTTP_VERB verb = req.verb();
    bool readOnly = verb == HttpVerbGET || verb == HttpVerbHEAD;
    if (!readOnly) {
        // CSRF: same-origin requests only, JSON bodies only.
        if (req.header("Origin") != AdminOrigin()) { JsonError(resp, 403, "Cross-origin request refused."); return; }
        std::string ct = ToLowerAscii(req.header(HttpHeaderContentType));
        if (req.hasBody() && ct.rfind("application/json", 0) != 0) { JsonError(resp, 415, "Expected application/json."); return; }
    }

    if (path == L"/status" && readOnly) return ApiStatus(resp);
    if (path == L"/sites") {
        if (readOnly) return ApiSites(resp);
        if (verb == HttpVerbPOST) return ApiCreateSite(req, resp);
    }
    if (path.substr(0, 7) == L"/sites/") {
        auto id = ParseId(path.substr(7));
        if (!id) { JsonError(resp, 404, "No such site."); return; }
        if (verb == HttpVerbPUT) return ApiUpdateSite(req, resp, *id);
        if (verb == HttpVerbDELETE) return ApiDeleteSite(resp, *id);
        if (readOnly) {
            auto s = store_.GetSite(*id);
            if (!s) { JsonError(resp, 404, "No such site."); return; }
            Json(resp, 200, SiteJson(*s, recon_.status()));
            return;
        }
    }
    if (path == L"/fs" && readOnly) return ApiBrowse(req, resp);
    if (path == L"/settings" && (verb == HttpVerbPUT)) return ApiSettings(req, resp);
    if (path == L"/logout" && verb == HttpVerbPOST) {
        std::string sid = CookieValue(req.header(HttpHeaderCookie), kCookie);
        { std::lock_guard lk(mu_); sessions_.erase(sid); }
        resp.set("Set-Cookie", std::string(kCookie) + "=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
        Json(resp, 200, json::Value::Object());
        return;
    }
    JsonError(resp, 404, "Unknown API endpoint.");
}

json::Value Admin::SiteJson(const Site& s, const std::map<std::string, std::vector<std::string>>& status) {
    json::Value v = json::Value::Object();
    v.set("id", json::Value::Number(double(s.id)));
    v.set("name", json::Value::String(s.name));
    v.set("host", json::Value::String(s.host));
    v.set("port", json::Value::Number(s.port));
    v.set("root", s.rootPath.empty() ? json::Value() : json::Value::String(s.rootPath));
    v.set("enabled", json::Value::Bool(s.enabled));
    v.set("dirListing", json::Value::Bool(s.dirListing));
    v.set("serveHidden", json::Value::Bool(s.serveHidden));
    v.set("cacheControl", json::Value::String(s.cacheControl));
    v.set("url", json::Value::String("https://" + s.host + (s.port == 443 ? "" : ":" + std::to_string(s.port)) + "/"));
    json::Value errs = json::Value::Array();
    auto it = status.find(Reconciler::Key(s.host, s.port));
    if (it != status.end()) for (auto& e : it->second) errs.push(json::Value::String(e));
    v.set("errors", std::move(errs));
    return v;
}

bool Admin::ValidateRoot(std::string& root, std::string& error) {
    std::wstring w = FromUtf8(root);
    while (w.size() > 3 && (w.back() == L'\\' || w.back() == L'/')) w.pop_back();
    for (auto& c : w) if (c == L'/') c = L'\\';
    if (!IsDrivePath(w)) { error = "Folder must be a full local path such as D:\\Sites\\blog."; return false; }
    if (w.find(L"\\\\") != std::wstring::npos || w.find(L"\\.\\") != std::wstring::npos ||
        w.find(L"\\..") != std::wstring::npos) {
        error = "Folder path must not contain '.' or '..' segments.";
        return false;
    }
    DWORD err = 0;
    std::wstring finalPath = FinalPathOfDirectory(w, &err);
    if (finalPath.empty()) { error = "Folder not found or not accessible: " + ErrorTextUtf8(err); return false; }
    if (StartsWithNoCase(finalPath, L"\\\\?\\UNC\\")) { error = "Network folders are not supported."; return false; }
    if (!dataDirFinal_.empty() && (IsWithin(finalPath, dataDirFinal_) || IsWithin(dataDirFinal_, finalPath))) {
        error = "That folder contains (or is inside) wsrv's private configuration directory.";
        return false;
    }
    root = ToUtf8(w);
    return true;
}

bool Admin::SiteFromJson(const json::Value& v, Site& s, std::string& error) {
    if (!v.isObject()) { error = "Expected a JSON object."; return false; }
    if (auto* p = v.get("host")) {
        if (!p->isString()) { error = "host must be a string."; return false; }
        s.host = ToLowerAscii(std::string(Trim(p->asString())));
    }
    if (!IsValidAlias(s.host, &error)) return false;
    if (auto* p = v.get("name")) {
        if (!p->isString()) { error = "name must be a string."; return false; }
        s.name = std::string(Trim(p->asString()));
    }
    if (s.name.empty()) s.name = s.host;
    if (s.name.size() > 100) { error = "Name is too long."; return false; }
    if (auto* p = v.get("port")) {
        if (!p->isNumber() || p->asNumber() != double(int(p->asNumber())) || p->asNumber() < 1 || p->asNumber() > 65535) {
            error = "Port must be a whole number between 1 and 65535.";
            return false;
        }
        s.port = int(p->asNumber());
    }
    if (auto* p = v.get("root")) {
        if (p->isNull() || (p->isString() && Trim(p->asString()).empty())) s.rootPath.clear();
        else if (p->isString()) {
            s.rootPath = std::string(Trim(p->asString()));
            if (!ValidateRoot(s.rootPath, error)) return false;
        } else { error = "root must be a string or null."; return false; }
    }
    auto flag = [&](const char* key, bool& field) {
        if (auto* p = v.get(key)) {
            if (!p->isBool()) { error = std::string(key) + " must be true or false."; return false; }
            field = p->asBool();
        }
        return true;
    };
    if (!flag("enabled", s.enabled) || !flag("dirListing", s.dirListing) || !flag("serveHidden", s.serveHidden)) return false;
    if (auto* p = v.get("cacheControl")) {
        if (!p->isString()) { error = "cacheControl must be a string."; return false; }
        std::string cc(Trim(p->asString()));
        if (cc.size() > 200) { error = "Cache-Control is too long."; return false; }
        for (char c : cc)
            if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) { error = "Cache-Control contains invalid characters."; return false; }
        s.cacheControl = cc.empty() ? "no-cache" : cc;
    }
    return true;
}

void Admin::ApiStatus(Response& resp) {
    auto sites = store_.ListSites();
    json::Value v = json::Value::Object();
    v.set("version", json::Value::String(kVersion));
    v.set("http3Enabled", json::Value::Bool(ReadHttpParameter(L"EnableHttp3").value_or(0) != 0));
    v.set("altSvcEnabled", json::Value::Bool(ReadHttpParameter(L"EnableAltSvc").value_or(0) != 0));
    v.set("dataDir", json::Value::String(ToUtf8(DefaultDataDir())));
    v.set("accessLog", json::Value::Bool(log::AccessLogEnabled()));
    v.set("edgeCommand", json::Value::String(EdgeCommand(sites)));
    bool anyMapped = false;
    for (auto& s : sites) if (s.enabled && !s.rootPath.empty()) anyMapped = true;
    v.set("helloFallback", json::Value::Bool(!anyMapped));
    json::Value errs = json::Value::Array();
    auto status = recon_.status();
    for (auto& [key, list] : status) {
        bool own = key == Reconciler::Key(ToUtf8(kAdminHost), kAdminPort) || key == "localhost:443";
        if (own) for (auto& e : list) errs.push(json::Value::String(key + ": " + e));
    }
    v.set("errors", std::move(errs));
    Json(resp, 200, v);
}

void Admin::ApiSites(Response& resp) {
    auto status = recon_.status();
    json::Value arr = json::Value::Array();
    for (auto& s : store_.ListSites()) arr.push(SiteJson(s, status));
    Json(resp, 200, arr);
}

void Admin::ApiCreateSite(Request& req, Response& resp) {
    std::string body;
    if (!req.readBody(body, kMaxBody)) { JsonError(resp, 413, "Request body too large."); return; }
    auto v = json::Parse(body);
    if (!v) { JsonError(resp, 400, "Invalid JSON."); return; }
    Site s;
    std::string error;
    if (!SiteFromJson(*v, s, error)) { JsonError(resp, 400, error); return; }
    if (!store_.InsertSite(s, &error)) { JsonError(resp, 409, error); return; }
    log::Info("Site added: " + s.host + ":" + std::to_string(s.port));
    recon_.Apply();
    Json(resp, 201, SiteJson(s, recon_.status()));
}

void Admin::ApiUpdateSite(Request& req, Response& resp, int64_t id) {
    auto existing = store_.GetSite(id);
    if (!existing) { JsonError(resp, 404, "No such site."); return; }
    std::string body;
    if (!req.readBody(body, kMaxBody)) { JsonError(resp, 413, "Request body too large."); return; }
    auto v = json::Parse(body);
    if (!v) { JsonError(resp, 400, "Invalid JSON."); return; }
    Site s = *existing;
    std::string error;
    if (!SiteFromJson(*v, s, error)) { JsonError(resp, 400, error); return; }
    if (!store_.UpdateSite(s, &error)) { JsonError(resp, 409, error); return; }
    log::Info("Site updated: " + s.host + ":" + std::to_string(s.port));
    recon_.Apply();
    Json(resp, 200, SiteJson(s, recon_.status()));
}

void Admin::ApiDeleteSite(Response& resp, int64_t id) {
    auto existing = store_.GetSite(id);
    if (!existing || !store_.DeleteSite(id)) { JsonError(resp, 404, "No such site."); return; }
    log::Info("Site removed: " + existing->host + ":" + std::to_string(existing->port));
    recon_.Apply();
    Json(resp, 200, json::Value::Object());
}

void Admin::ApiBrowse(Request& req, Response& resp) {
    std::wstring path = FromUtf8(QueryParam(ToUtf8(req.query()), "path").value_or(""));
    json::Value v = json::Value::Object();
    json::Value dirs = json::Value::Array();
    auto entry = [](const std::wstring& name, const std::wstring& full) {
        json::Value e = json::Value::Object();
        e.set("name", json::Value::String(ToUtf8(name)));
        e.set("path", json::Value::String(ToUtf8(full)));
        return e;
    };

    if (path.empty()) {
        wchar_t drives[512];
        DWORD n = GetLogicalDriveStringsW(512, drives);
        for (wchar_t* d = drives; d < drives + n && *d; d += wcslen(d) + 1) {
            UINT type = GetDriveTypeW(d);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_RAMDISK) dirs.push(entry(d, d));
        }
        v.set("path", json::Value::String(""));
        v.set("parent", json::Value());
        v.set("dirs", std::move(dirs));
        Json(resp, 200, v);
        return;
    }

    for (auto& c : path) if (c == L'/') c = L'\\';
    if (!IsDrivePath(path) || path.find(L"\\..") != std::wstring::npos) { JsonError(resp, 400, "Invalid folder path."); return; }
    if (path.back() != L'\\') path += L'\\';

    std::vector<std::wstring> names;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW((path + L"*").c_str(), FindExInfoBasic, &fd, FindExSearchLimitToDirectories, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) { JsonError(resp, 404, "Folder not accessible: " + ErrorTextUtf8(GetLastError())); return; }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) && (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)) continue;
        std::wstring_view name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        names.emplace_back(name);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(names.begin(), names.end(), [](auto& a, auto& b) {
        return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    });
    for (auto& n : names) dirs.push(entry(n, path + n));

    std::wstring display = path.size() > 3 ? path.substr(0, path.size() - 1) : path;
    std::wstring parent;
    if (display.size() > 3) {
        size_t slash = display.find_last_of(L'\\');
        parent = slash <= 2 ? display.substr(0, 3) : display.substr(0, slash);
    }
    v.set("path", json::Value::String(ToUtf8(display)));
    v.set("parent", json::Value::String(ToUtf8(parent)));
    v.set("dirs", std::move(dirs));
    Json(resp, 200, v);
}

void Admin::ApiSettings(Request& req, Response& resp) {
    std::string body;
    if (!req.readBody(body, kMaxBody)) { JsonError(resp, 413, "Request body too large."); return; }
    auto v = json::Parse(body);
    if (!v || !v->isObject()) { JsonError(resp, 400, "Invalid JSON."); return; }
    if (auto* p = v->get("accessLog")) {
        if (!p->isBool()) { JsonError(resp, 400, "accessLog must be true or false."); return; }
        store_.SetSetting("access_log", p->asBool() ? "1" : "0");
        log::SetAccessLog(p->asBool());
    }
    ApiStatus(resp);
}

} // namespace wsrv
