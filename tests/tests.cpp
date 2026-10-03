// wsrv unit tests. No framework: CHECK records failures, main() reports and returns non-zero on failure.
#include "admin.h"
#include "certs.h"
#include "config_store.h"
#include "handlers.h"
#include "httpsys.h"
#include "hosts_file.h"
#include "http_util.h"
#include "json.h"
#include "log.h"
#include "path_guard.h"
#include "util.h"

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

using namespace wsrv;

static int g_checks = 0, g_failures = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        ++g_checks;                                                                    \
        if (!(cond)) {                                                                 \
            ++g_failures;                                                              \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
        }                                                                              \
    } while (0)

static void Run(const char* name, const std::function<void()>& fn) {
    int before = g_failures;
    printf("%s\n", name);
    fn();
    if (g_failures == before) printf("  ok\n");
}

// ---------------------------------------------------------------------------------------------

static void TestUtil() {
    CHECK(UrlDecode("a%20b%2Fc").value() == "a b/c");
    CHECK(!UrlDecode("bad%2").has_value());
    CHECK(!UrlDecode("bad%zz").has_value());
    CHECK(QueryParam("?t=abc&x=1", "t").value() == "abc");
    CHECK(QueryParam("path=C%3A%5CUsers+x", "path").value() == "C:\\Users x");
    CHECK(!QueryParam("a=1", "t").has_value());
    CHECK(UrlEncodePath("/a b/é.html") == "/a%20b/%C3%A9.html");
    CHECK(HtmlEscape("<a href=\"x\">&'") == "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    CHECK(FormatHttpDate(784111777) == "Sun, 06 Nov 1994 08:49:37 GMT");
    CHECK(ParseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT").value() == 784111777);
    CHECK(!ParseHttpDate("Sunday, 06-Nov-94 08:49:37 GMT").has_value());
    CHECK(!ParseHttpDate("garbage").has_value());
    CHECK(ConstantTimeEquals("abc", "abc") && !ConstantTimeEquals("abc", "abd") && !ConstantTimeEquals("a", "ab"));
    CHECK(RandomHex(16).size() == 32 && RandomHex(16) != RandomHex(16));
    CHECK(ToUtf8(FromUtf8("héllo ✓")) == "héllo ✓");
}

static void TestJson() {
    auto v = json::Parse(R"({"a":1,"b":[true,false,null],"c":"x\"y\u00e9\ud83d\ude00","d":{"e":-2.5}})");
    CHECK(v.has_value());
    CHECK(v->get("a")->asNumber() == 1);
    CHECK(v->get("b")->items().size() == 3 && v->get("b")->items()[2].isNull());
    CHECK(v->get("c")->asString() == "x\"y\xC3\xA9\xF0\x9F\x98\x80");
    CHECK(v->get("d")->get("e")->asNumber() == -2.5);
    CHECK(!json::Parse("{\"a\":}").has_value());
    CHECK(!json::Parse("[1,2").has_value());
    CHECK(!json::Parse("{\"a\":1} trailing").has_value());
    CHECK(!json::Parse("\"\\ud800\"").has_value());
    std::string deep(100, '[');
    CHECK(!json::Parse(deep + std::string(100, ']')).has_value());  // depth limit
    json::Value o = json::Value::Object();
    o.set("s", json::Value::String("<script>\n"));
    o.set("n", json::Value::Number(42));
    CHECK(o.dump() == R"({"s":"\u003cscript>\n","n":42})");
}

static void TestRanges() {
    auto r = ParseRange("bytes=0-99", 1000);
    CHECK(r.kind == ByteRange::Kind::Satisfiable && r.start == 0 && r.length == 100);
    r = ParseRange("bytes=900-", 1000);
    CHECK(r.kind == ByteRange::Kind::Satisfiable && r.start == 900 && r.length == 100);
    r = ParseRange("bytes=-100", 1000);
    CHECK(r.kind == ByteRange::Kind::Satisfiable && r.start == 900 && r.length == 100);
    r = ParseRange("bytes=-5000", 1000);
    CHECK(r.kind == ByteRange::Kind::Satisfiable && r.start == 0 && r.length == 1000);
    r = ParseRange("bytes=500-99999", 1000);
    CHECK(r.kind == ByteRange::Kind::Satisfiable && r.length == 500);
    CHECK(ParseRange("bytes=1000-", 1000).kind == ByteRange::Kind::Unsatisfiable);
    CHECK(ParseRange("bytes=-0", 1000).kind == ByteRange::Kind::Unsatisfiable);
    CHECK(ParseRange("bytes=0-1,5-6", 1000).kind == ByteRange::Kind::None);
    CHECK(ParseRange("bytes=9-3", 1000).kind == ByteRange::Kind::None);
    CHECK(ParseRange("items=0-1", 1000).kind == ByteRange::Kind::None);
    CHECK(ParseRange("bytes=abc", 1000).kind == ByteRange::Kind::None);
    CHECK(ParseRange("bytes=0-", 0).kind == ByteRange::Kind::Unsatisfiable);
}

static void TestConditionals() {
    std::string etag = MakeEtag(0x1a2b, 0x123456789);
    CHECK(etag == "\"1a2b-123456789\"");
    CHECK(IfNoneMatchMatches(etag, etag));
    CHECK(IfNoneMatchMatches("W/" + etag, etag));
    CHECK(IfNoneMatchMatches("\"x\", " + etag, etag));
    CHECK(IfNoneMatchMatches("*", etag));
    CHECK(!IfNoneMatchMatches("\"other\"", etag));
    CHECK(IfRangeAllows(etag, etag, 0));
    CHECK(!IfRangeAllows("W/" + etag, etag, 0));
    CHECK(IfRangeAllows("Sun, 06 Nov 1994 08:49:37 GMT", etag, 784111777));
    CHECK(!IfRangeAllows("Sun, 06 Nov 1994 08:49:38 GMT", etag, 784111777));
    CHECK(AcceptsEncoding("gzip, deflate, br, zstd", "br"));
    CHECK(!AcceptsEncoding("gzip;q=1, br;q=0", "br"));
    CHECK(!AcceptsEncoding("gzip", "br"));
}

static void TestMimeAndAlias() {
    CHECK(MimeTypeFor("HTML") == "text/html; charset=utf-8");
    CHECK(MimeTypeFor("wasm") == "application/wasm");
    CHECK(MimeTypeFor("unknownext") == "application/octet-stream");
    std::map<std::string, std::string> o{{"md", "text/plain"}};
    CHECK(MimeTypeFor("md", &o) == "text/plain");
    CHECK(IsValidAlias("local.blog"));
    CHECK(IsValidAlias("local.my-site.dev"));
    CHECK(!IsValidAlias("local.admin"));
    CHECK(!IsValidAlias("blog.local"));
    CHECK(!IsValidAlias("local."));
    CHECK(!IsValidAlias("local.Blog"));
    CHECK(!IsValidAlias("local.-x"));
    CHECK(!IsValidAlias("local.a..b"));
    CHECK(!IsValidAlias("local.a_b"));
    CHECK(!IsValidAlias("example.com"));
}

static void TestSanitize() {
    std::wstring rel;
    bool slash = false;
    auto ok = [&](const wchar_t* p) { return SanitizeUrlPath(p, rel, slash) == GuardResult::Ok; };

    CHECK(ok(L"/") && rel.empty() && slash);
    CHECK(ok(L"/a/b.html") && rel == L"a\\b.html" && !slash);
    CHECK(ok(L"/a//b/") && rel == L"a\\b" && slash);
    CHECK(ok(L"/caf\u00e9/\u65e5\u672c.txt"));
    CHECK(ok(L"/file~1.txt"));  // ordinary name; final-path check handles 8.3 aliasing

    // Traversal corpus (paths as decoded by http.sys).
    const wchar_t* bad[] = {
        L"", L"a", L"/..", L"/../x", L"/a/../../x", L"/./x", L"/a/./b", L"/a\\..\\..\\x", L"/a\\b",
        L"/C:/Windows/win.ini", L"/C:", L"/file.txt::$DATA", L"/file:stream", L"/CON", L"/con.txt", L"/aux.html",
        L"/NUL", L"/com1", L"/LPT9.log", L"/COM\u00b9", L"/CONIN$", L"/conout$", L"/x/prn/y", L"/a./", L"/a.",
        L"/a ", L"/name. ", L"/a\u0001b", L"/a|b", L"/a*b", L"/a?b", L"/a\"b", L"/a<b", L"/a>b",
    };
    for (auto p : bad) {
        bool rejected = SanitizeUrlPath(p, rel, slash) != GuardResult::Ok;
        if (!rejected) printf("  accepted: %ls\n", p);
        CHECK(rejected);
    }
    std::wstring withNul = L"/a";
    withNul.push_back(L'\0');
    withNul += L"b";
    CHECK(SanitizeUrlPath(withNul, rel, slash) != GuardResult::Ok);
    std::wstring longSeg = L"/" + std::wstring(300, L'a');
    CHECK(SanitizeUrlPath(longSeg, rel, slash) != GuardResult::Ok);

    CHECK(IsForbiddenSegment(L"CON"));
    CHECK(IsForbiddenSegment(L"con .txt"));
    CHECK(!IsForbiddenSegment(L"console.txt"));
    CHECK(!IsForbiddenSegment(L"com10"));
    CHECK(!IsForbiddenSegment(L"lpt"));
}

static void TestIsWithin() {
    CHECK(IsWithin(L"\\\\?\\C:\\site", L"\\\\?\\C:\\site"));
    CHECK(IsWithin(L"\\\\?\\C:\\site", L"\\\\?\\c:\\SITE\\a.html"));
    CHECK(!IsWithin(L"\\\\?\\C:\\site", L"\\\\?\\C:\\site-evil\\a.html"));
    CHECK(!IsWithin(L"\\\\?\\C:\\site", L"\\\\?\\C:\\sit"));
    CHECK(!IsWithin(L"\\\\?\\C:\\site", L"\\\\?\\D:\\site\\a"));
    CHECK(IsWithin(L"\\\\?\\C:\\", L"\\\\?\\C:\\anything"));
    CHECK(!IsWithin(L"", L"\\\\?\\C:\\x"));
}

// Filesystem-backed containment tests in a temporary tree:
//   <tmp>\root\index.html, sub\a.txt, .env, hidden.txt (hidden), data\ (forbidden), escape -> junction to outside
//   <tmp>\outside\secret.txt, <tmp>\root-evil\x.txt
static void WriteFileText(const std::wstring& path, const char* text) {
    UniqueHandle h(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    DWORD n = 0;
    WriteFile(h.get(), text, (DWORD)strlen(text), &n, nullptr);
}

static void TestContainment() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring base = std::wstring(tmp) + L"wsrv-test-" + FromUtf8(RandomHex(4));
    std::wstring root = base + L"\\root", outside = base + L"\\outside", evil = base + L"\\root-evil";
    CreateDirectoryW(base.c_str(), nullptr);
    CreateDirectoryW(root.c_str(), nullptr);
    CreateDirectoryW((root + L"\\sub").c_str(), nullptr);
    CreateDirectoryW((root + L"\\data").c_str(), nullptr);
    CreateDirectoryW((root + L"\\.git").c_str(), nullptr);
    CreateDirectoryW(outside.c_str(), nullptr);
    CreateDirectoryW(evil.c_str(), nullptr);
    WriteFileText(root + L"\\index.html", "<h1>hi</h1>");
    WriteFileText(root + L"\\sub\\a.txt", "a");
    WriteFileText(root + L"\\.env", "SECRET=1");
    WriteFileText(root + L"\\.git\\config", "x");
    WriteFileText(root + L"\\hidden.txt", "h");
    SetFileAttributesW((root + L"\\hidden.txt").c_str(), FILE_ATTRIBUTE_HIDDEN);
    WriteFileText(root + L"\\data\\wsrv.db", "db");
    WriteFileText(outside + L"\\secret.txt", "secret");
    WriteFileText(evil + L"\\x.txt", "x");

    std::wstring junctionCmd = L"cmd /c mklink /J \"" + root + L"\\escape\" \"" + outside + L"\" >nul 2>&1";
    bool haveJunction = _wsystem(junctionCmd.c_str()) == 0;
    std::wstring linkCmd = L"cmd /c mklink \"" + root + L"\\link.txt\" \"" + outside + L"\\secret.txt\" >nul 2>&1";
    bool haveSymlink = _wsystem(linkCmd.c_str()) == 0;

    GuardPolicy policy;
    policy.rootFinal = FinalPathOfDirectory(root);
    policy.forbiddenFinal = FinalPathOfDirectory(root + L"\\data");
    CHECK(!policy.rootFinal.empty());

    ContainedFile f;
    CHECK(OpenContained(policy, L"index.html", f) == GuardResult::Ok && !f.isDirectory() && f.size() == 11);
    CHECK(OpenContained(policy, L"", f) == GuardResult::Ok && f.isDirectory());
    CHECK(OpenContained(policy, L"sub\\a.txt", f) == GuardResult::Ok);
    CHECK(OpenContained(policy, L"SUB\\A.TXT", f) == GuardResult::Ok);
    CHECK(OpenContained(policy, L"missing.txt", f) == GuardResult::NotFound);
    CHECK(OpenContained(policy, L".env", f) == GuardResult::NotFound);
    CHECK(OpenContained(policy, L".git\\config", f) == GuardResult::NotFound);
    CHECK(OpenContained(policy, L"hidden.txt", f) == GuardResult::NotFound);
    CHECK(OpenContained(policy, L"data\\wsrv.db", f) == GuardResult::NotFound);
    CHECK(OpenContained(policy, L"data", f) == GuardResult::NotFound);
    // Even an unsanitized ".." can't escape: \\?\ paths are literal and the final path is checked.
    CHECK(OpenContained(policy, L"..\\outside\\secret.txt", f) != GuardResult::Ok);
    CHECK(OpenContained(policy, L"..\\root-evil\\x.txt", f) != GuardResult::Ok);
    if (haveJunction) {
        CHECK(OpenContained(policy, L"escape\\secret.txt", f) == GuardResult::NotFound);
        CHECK(OpenContained(policy, L"escape", f) == GuardResult::NotFound);
    } else {
        printf("  (junction test skipped)\n");
    }
    if (haveSymlink) CHECK(OpenContained(policy, L"link.txt", f) == GuardResult::NotFound);
    else printf("  (file symlink test skipped: needs Developer Mode or elevation)\n");

    // 8.3 alias of ".env" must not bypass the dot-file rule.
    wchar_t shortName[MAX_PATH];
    if (GetShortPathNameW((root + L"\\.env").c_str(), shortName, MAX_PATH)) {
        std::wstring s = shortName;
        std::wstring leaf = s.substr(s.find_last_of(L'\\') + 1);
        if (leaf != L".env") CHECK(OpenContained(policy, leaf, f) == GuardResult::NotFound);
    }

    GuardPolicy open = policy;
    open.serveHidden = true;
    CHECK(OpenContained(open, L".env", f) == GuardResult::Ok);
    CHECK(OpenContained(open, L"hidden.txt", f) == GuardResult::Ok);
    CHECK(OpenContained(open, L"data\\wsrv.db", f) == GuardResult::NotFound);  // forbidden even when hidden allowed
    if (haveJunction) CHECK(OpenContained(open, L"escape\\secret.txt", f) == GuardResult::NotFound);
    f.handle.reset();

    _wsystem((L"cmd /c rmdir /s /q \"" + base + L"\" >nul 2>&1").c_str());
}

static void TestHostsBlock() {
    std::string original = "# comment\r\n127.0.0.1 example.test\r\n";
    std::string a = hosts::ApplyBlock(original, {"local.admin", "local.blog"});
    CHECK(a.find("127.0.0.1 example.test") != std::string::npos);
    CHECK(a.find("127.0.0.1 local.blog\r\n") != std::string::npos);
    CHECK(a.find("::1 local.admin\r\n") != std::string::npos);
    std::string b = hosts::ApplyBlock(a, {"local.admin"});
    CHECK(b.find("local.blog") == std::string::npos);
    CHECK(hosts::ApplyBlock(b, {"local.admin"}) == b);  // idempotent
    CHECK(hosts::ApplyBlock(b, {}) == original);
    CHECK(hosts::ApplyBlock("no newline", {"local.x"}).rfind("no newline\r\n# BEGIN", 0) == 0);
}

static void TestConfigStore() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + L"wsrv-test-" + FromUtf8(RandomHex(4)) + L".db";
    {
        ConfigStore store;
        std::string err;
        CHECK(store.Open(path, &err));
        Site s;
        s.name = "Blog";
        s.host = "local.blog";
        s.port = 443;
        s.rootPath = "D:\\Sites\\blog";
        CHECK(store.InsertSite(s, &err) && s.id > 0);
        Site dup = s;
        CHECK(!store.InsertSite(dup, &err) && err.find("already") != std::string::npos);
        dup.port = 8443;
        CHECK(store.InsertSite(dup, &err));
        auto got = store.GetSite(s.id);
        CHECK(got && got->rootPath == "D:\\Sites\\blog" && got->enabled && got->cacheControl == "no-cache");
        got->rootPath.clear();
        got->enabled = false;
        CHECK(store.UpdateSite(*got, &err));
        got = store.GetSite(s.id);
        CHECK(got && got->rootPath.empty() && !got->enabled);
        CHECK(store.ListSites().size() == 2);
        CHECK(store.DeleteSite(dup.id) && !store.DeleteSite(dup.id));
        store.SetSetting("k", "v1");
        store.SetSetting("k", "v2");
        CHECK(store.GetSetting("k").value() == "v2");
        store.PutCert({"local.blog", "aa", "bb", "key", 123});
        CHECK(store.GetCert("local.blog")->notAfter == 123);
        store.DeleteCert("local.blog");
        CHECK(!store.GetCert("local.blog"));
        store.PutBinding({"local.blog", 443});
        store.PutBinding({"local.blog", 443});
        CHECK(store.ListBindings().size() == 1);
    }
    {
        ConfigStore reopened;  // migrations are idempotent
        std::string err;
        CHECK(reopened.Open(path, &err) && reopened.ListSites().size() == 1);
    }
    DeleteFileW(path.c_str());
    DeleteFileW((path + L"-wal").c_str());
    DeleteFileW((path + L"-shm").c_str());
}

// ---------------------------------------------------------------------------------------------
// Over-the-wire tests against real http.sys, using the built-in Everyone-allowed reservation
// http://+:80/Temporary_Listen_Addresses/ (no elevation needed). The web root mirrors that prefix.

struct RawResponse {
    int status = 0;
    std::map<std::string, std::string> headers;  // lower-case names
    std::string body;
    std::string header(const char* name) const {
        auto it = headers.find(name);
        return it == headers.end() ? std::string() : it->second;
    }
};

static RawResponse SendRaw(const std::string& request) {
    RawResponse r;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) { closesocket(s); return r; }
    send(s, request.data(), (int)request.size(), 0);
    std::string raw;
    char buf[8192];
    int n;
    while ((n = recv(s, buf, sizeof buf, 0)) > 0) raw.append(buf, n);
    closesocket(s);
    size_t headerEnd = raw.find("\r\n\r\n");
    if (headerEnd == std::string::npos || raw.size() < 12) return r;
    r.status = atoi(raw.c_str() + 9);
    size_t pos = raw.find("\r\n") + 2;
    while (pos < headerEnd) {
        size_t eol = raw.find("\r\n", pos);
        std::string line = raw.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) r.headers[ToLowerAscii(line.substr(0, colon))] = std::string(Trim(line.substr(colon + 1)));
        pos = eol + 2;
    }
    r.body = raw.substr(headerEnd + 4);
    return r;
}

static RawResponse Get(const std::string& path, const std::string& extra = "", const char* verb = "GET") {
    return SendRaw(std::string(verb) + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" + extra + "\r\n");
}

static void TestHttpEngine() {
    std::string tag = "wsrv-" + RandomHex(4);
    std::string prefix = "/Temporary_Listen_Addresses/" + tag;
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring base = std::wstring(tmp) + L"wsrv-wire-" + FromUtf8(RandomHex(4));
    std::wstring root = base + L"\\root";
    std::wstring site = root + L"\\Temporary_Listen_Addresses\\" + FromUtf8(tag);
    std::wstring outside = base + L"\\outside";
    for (auto& d : {base, root, root + L"\\Temporary_Listen_Addresses", site, site + L"\\sub", outside})
        CreateDirectoryW(d.c_str(), nullptr);
    WriteFileText(site + L"\\index.html", "<h1>wsrv</h1>");
    WriteFileText(site + L"\\app.js", "console.log('plain')");
    WriteFileText(site + L"\\app.js.br", "BROTLI");
    WriteFileText(site + L"\\.env", "SECRET=1");
    WriteFileText(site + L"\\sub\\a.txt", "a");
    std::string big;
    for (int i = 0; i < 1000; ++i) big += char('0' + i % 10);
    WriteFileText(site + L"\\big.bin", big.c_str());
    WriteFileText(outside + L"\\secret.txt", "TOPSECRET");
    _wsystem((L"cmd /c mklink /J \"" + site + L"\\escape\" \"" + outside + L"\" >nul 2>&1").c_str());

    SiteRuntime rt;
    rt.site.cacheControl = "no-cache";
    rt.site.rootPath = ToUtf8(root);
    rt.policy.rootFinal = FinalPathOfDirectory(root);
    std::map<std::string, std::string> mime;

    HttpApiScope api;
    CHECK(api.ok());
    HttpServer server;
    std::string err;
    bool started = server.Start([&](Request& q, Response& r) { ServeStatic(rt, mime, q, r); }, &err);
    CHECK(started);
    DWORD add = server.AddUrl(L"http://+:80" + FromUtf8(prefix) + L"/", 1);
    if (!started || add != NO_ERROR) {
        printf("  http.sys unavailable (%s / %lu); skipping wire tests\n", err.c_str(), add);
        return;
    }
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    auto r = Get(prefix + "/");
    CHECK(r.status == 200 && r.body == "<h1>wsrv</h1>");
    CHECK(r.header("content-type") == "text/html; charset=utf-8");
    CHECK(r.header("content-length") == "13");
    CHECK(r.header("alt-svc") == "h3=\":80\"; ma=86400");
    CHECK(r.header("x-content-type-options") == "nosniff");
    std::string etag = r.header("etag");
    CHECK(!etag.empty());

    auto h = Get(prefix + "/", "", "HEAD");
    CHECK(h.status == 200 && h.body.empty() && h.header("content-length") == "13" && h.header("etag") == etag);

    CHECK(Get(prefix + "/", "If-None-Match: " + etag + "\r\n").status == 304);
    CHECK(Get(prefix + "/", "If-None-Match: \"nope\"\r\n").status == 200);
    CHECK(Get(prefix + "/", "If-Modified-Since: " + r.header("last-modified") + "\r\n").status == 304);

    auto part = Get(prefix + "/big.bin", "Range: bytes=10-19\r\n");
    CHECK(part.status == 206 && part.body == "0123456789" && part.header("content-range") == "bytes 10-19/1000");
    CHECK(Get(prefix + "/big.bin", "Range: bytes=5000-\r\n").status == 416);
    CHECK(Get(prefix + "/big.bin", "Range: bytes=0-1\r\nIf-Range: \"stale\"\r\n").status == 200);

    for (const char* verb : {"POST", "PUT", "DELETE", "OPTIONS", "PATCH", "PROPFIND"}) {
        auto m = Get(prefix + "/", "Content-Length: 0\r\n", verb);
        CHECK(m.status == 405 && m.header("allow") == "GET, HEAD");
    }

    auto redir = Get(prefix + "/sub");
    CHECK(redir.status == 301 && redir.header("location") == prefix + "/sub/");
    CHECK(Get(prefix + "/sub/").status == 404);  // no index, listing off
    rt.site.dirListing = true;
    auto listing = Get(prefix + "/sub/");
    CHECK(listing.status == 200 && listing.body.find("a.txt") != std::string::npos);
    auto rootListing = Get(prefix + "/");  // index.html still wins
    CHECK(rootListing.body == "<h1>wsrv</h1>");
    rt.site.dirListing = false;

    auto br = Get(prefix + "/app.js", "Accept-Encoding: gzip, br\r\n");
    CHECK(br.status == 200 && br.header("content-encoding") == "br" && br.body == "BROTLI" &&
          br.header("vary") == "Accept-Encoding" && br.header("content-type") == "text/javascript; charset=utf-8");
    auto plain = Get(prefix + "/app.js");
    CHECK(plain.status == 200 && plain.header("content-encoding").empty() && plain.body == "console.log('plain')");
    CHECK(br.header("etag") != plain.header("etag"));

    // Escapes and forbidden names over the wire: nothing may return the secret.
    const char* attacks[] = {
        "/.env", "/escape/secret.txt", "/%2e%2e/%2e%2e/%2e%2e/outside/secret.txt", "/..%2f..%2f..%2foutside%2fsecret.txt",
        "/..%5c..%5c..%5coutside%5csecret.txt", "/%252e%252e/%252e%252e/outside/secret.txt", "/%c0%ae%c0%ae/secret.txt",
        "/index.html::$DATA", "/index.html%3a%3a$DATA", "/CON", "/con.txt", "/index.html.", "/index.html%20",
        "/sub/..%00/index.html", "/C:/Windows/win.ini", "/%43:%5cWindows%5cwin.ini", "/escape%5csecret.txt",
        "/./.env", "/sub/../.env", "/ENV~1",
    };
    for (const char* a : attacks) {
        auto res = Get(prefix + a);
        bool leaked = res.body.find("TOPSECRET") != std::string::npos || res.body.find("SECRET=1") != std::string::npos;
        bool blocked = res.status != 200 && !leaked;
        if (!blocked) printf("  NOT BLOCKED: %s -> %d\n", a, res.status);
        CHECK(blocked);
    }
    // Escaping above the registered prefix lands outside wsrv's URL space entirely.
    auto above = Get("/Temporary_Listen_Addresses/" + tag + "/../../outside/secret.txt");
    CHECK(above.body.find("TOPSECRET") == std::string::npos);

    server.Stop();
    WSACleanup();
    _wsystem((L"cmd /c rmdir /s /q \"" + base + L"\" >nul 2>&1").c_str());
}

static void TestHello() {
    // Fabricated request: GET / and HEAD /.
    HTTP_REQUEST req{};
    req.Verb = HttpVerbGET;
    std::wstring path = L"/";
    req.CookedUrl.pAbsPath = path.c_str();
    req.CookedUrl.AbsPathLength = USHORT(path.size() * sizeof(wchar_t));
    Request r(nullptr, &req);
    Response resp;
    ServeHello(r, resp);
    CHECK(resp.status == 200 && resp.sendBody);
    CHECK(resp.body.find("Hello, world!") != std::string::npos);
    CHECK(resp.body.find("background:#000") != std::string::npos && resp.body.find("color:#fff") != std::string::npos);
    req.Verb = HttpVerbHEAD;
    Response head;
    ServeHello(r, head);
    CHECK(head.status == 200 && !head.sendBody && head.body == resp.body);
    req.Verb = HttpVerbPOST;
    Response post;
    ServeHello(r, post);
    CHECK(post.status == 405);
}

// A hand-built HTTP_REQUEST for driving handlers without the network.
struct FakeRequest {
    HTTP_REQUEST raw{};
    std::wstring path, query, host = L"local.admin:8192";
    std::string cookie, contentType, origin, body;
    HTTP_UNKNOWN_HEADER unknown{};
    HTTP_DATA_CHUNK chunk{};

    Response send(Admin& admin, HTTP_VERB verb) {
        raw = HTTP_REQUEST{};
        raw.Verb = verb;
        raw.CookedUrl.pAbsPath = path.c_str();
        raw.CookedUrl.AbsPathLength = USHORT(path.size() * sizeof(wchar_t));
        raw.CookedUrl.pQueryString = query.empty() ? nullptr : query.c_str();
        raw.CookedUrl.QueryStringLength = USHORT(query.size() * sizeof(wchar_t));
        raw.CookedUrl.pHost = host.c_str();
        raw.CookedUrl.HostLength = USHORT(host.size() * sizeof(wchar_t));
        auto setKnown = [&](HTTP_HEADER_ID id, const std::string& v) {
            raw.Headers.KnownHeaders[id].pRawValue = v.empty() ? nullptr : v.c_str();
            raw.Headers.KnownHeaders[id].RawValueLength = USHORT(v.size());
        };
        setKnown(HttpHeaderCookie, cookie);
        setKnown(HttpHeaderContentType, contentType);
        if (!origin.empty()) {
            unknown = {6, USHORT(origin.size()), "Origin", origin.c_str()};
            raw.Headers.UnknownHeaderCount = 1;
            raw.Headers.pUnknownHeaders = &unknown;
        }
        if (!body.empty()) {
            chunk.DataChunkType = HttpDataChunkFromMemory;
            chunk.FromMemory.pBuffer = body.data();
            chunk.FromMemory.BufferLength = ULONG(body.size());
            raw.EntityChunkCount = 1;
            raw.pEntityChunks = &chunk;
        }
        Request req(nullptr, &raw);
        Response resp;
        admin.Handle(req, resp);
        return resp;
    }
};

static void TestAdminApi() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring base = std::wstring(tmp) + L"wsrv-admin-" + FromUtf8(RandomHex(4));
    std::wstring data = base + L"\\data", site = base + L"\\site";
    CreateDirectoryW(base.c_str(), nullptr);
    CreateDirectoryW(data.c_str(), nullptr);
    CreateDirectoryW(site.c_str(), nullptr);
    std::wstring dataFinal = FinalPathOfDirectory(data);
    {
        ConfigStore store;
        std::string err;
        CHECK(store.Open(data + L"\\wsrv.db", &err));
        Reconciler recon(store, nullptr, dataFinal, /*manageMachine=*/false);
        recon.Apply();
        Admin admin(store, recon, dataFinal);

        FakeRequest f;
        f.path = L"/api/sites";
        f.host = L"evil.example:8192";
        CHECK(f.send(admin, HttpVerbGET).status == 421);  // DNS-rebinding guard
        f.host = L"local.admin:8192";
        CHECK(f.send(admin, HttpVerbGET).status == 401);  // not signed in

        f.path = L"/";
        auto page = f.send(admin, HttpVerbGET);
        CHECK(page.status == 200 && page.body.find("wsrv admin") != std::string::npos);
        CHECK(page.find("Content-Security-Policy") != nullptr);

        // Sign in with a one-time token.
        std::string token = admin.IssueLoginToken();
        f.path = L"/login";
        f.query = L"?t=wrong";
        CHECK(f.send(admin, HttpVerbGET).status == 403);
        f.query = L"?t=" + FromUtf8(token);
        auto login = f.send(admin, HttpVerbGET);
        CHECK(login.status == 303);
        const std::string* setCookie = login.find("Set-Cookie");
        CHECK(setCookie && setCookie->find("HttpOnly") != std::string::npos &&
              setCookie->find("SameSite=Strict") != std::string::npos && setCookie->find("Secure") != std::string::npos);
        CHECK(f.send(admin, HttpVerbGET).status == 403);  // token is single-use
        f.query.clear();
        f.cookie = setCookie ? setCookie->substr(0, setCookie->find(';')) : "";

        f.path = L"/api/sites";
        auto list = f.send(admin, HttpVerbGET);
        CHECK(list.status == 200 && list.body == "[]");

        // Create: CSRF checks first.
        f.contentType = "application/json";
        f.body = "{\"host\":\"local.blog\",\"port\":443,\"root\":" + json::Quote(ToUtf8(site)) + "}";
        CHECK(f.send(admin, HttpVerbPOST).status == 403);  // no Origin
        f.origin = "https://evil.example";
        CHECK(f.send(admin, HttpVerbPOST).status == 403);
        f.origin = "https://local.admin:8192";
        f.contentType = "text/plain";
        CHECK(f.send(admin, HttpVerbPOST).status == 415);
        f.contentType = "application/json";
        auto created = f.send(admin, HttpVerbPOST);
        CHECK(created.status == 201);
        auto cj = json::Parse(created.body);
        CHECK(cj && cj->get("host")->asString() == "local.blog" && cj->get("url")->asString() == "https://local.blog/");
        int64_t id = cj ? int64_t(cj->get("id")->asNumber()) : 0;

        CHECK(f.send(admin, HttpVerbPOST).status == 409);  // duplicate host:port

        auto bad = [&](const std::string& body) {
            f.body = body;
            auto r = f.send(admin, HttpVerbPOST);
            return r.status == 400;
        };
        CHECK(bad("{\"host\":\"blog.com\",\"port\":443}"));
        CHECK(bad("{\"host\":\"local.admin\",\"port\":443}"));
        CHECK(bad("{\"host\":\"local.x\",\"port\":70000}"));
        CHECK(bad("{\"host\":\"local.x\",\"port\":443,\"root\":\"relative\\\\path\"}"));
        CHECK(bad("{\"host\":\"local.x\",\"port\":443,\"root\":\"\\\\\\\\server\\\\share\"}"));
        CHECK(bad("{\"host\":\"local.x\",\"port\":443,\"root\":\"C:\\\\does-not-exist-" + RandomHex(4) + "\"}"));
        CHECK(bad("{\"host\":\"local.x\",\"port\":443,\"root\":" + json::Quote(ToUtf8(data)) + "}"));  // wsrv data dir
        CHECK(bad("{\"host\":\"local.x\",\"port\":443,\"root\":" + json::Quote(ToUtf8(base)) + "}"));  // contains it
        CHECK(bad("{\"host\":\"local.x\",\"port\":443,\"cacheControl\":\"x\\r\\nSet-Cookie: a=b\"}"));
        CHECK(bad("not json"));

        // A site with no folder (hello page).
        f.body = "{\"host\":\"local.hello\",\"port\":8443}";
        CHECK(f.send(admin, HttpVerbPOST).status == 201);

        // Update and delete.
        f.path = L"/api/sites/" + std::to_wstring(id);
        f.body = "{\"enabled\":false,\"name\":\"My blog\"}";
        auto upd = f.send(admin, HttpVerbPUT);
        CHECK(upd.status == 200 && upd.body.find("\"enabled\":false") != std::string::npos);
        CHECK(store.GetSite(id)->name == "My blog" && store.GetSite(id)->rootPath == ToUtf8(site));
        f.body.clear();
        f.contentType.clear();
        CHECK(f.send(admin, HttpVerbDELETE).status == 200);
        CHECK(f.send(admin, HttpVerbDELETE).status == 404);
        CHECK(store.ListSites().size() == 1);

        f.path = L"/api/status";
        auto st = f.send(admin, HttpVerbGET);
        CHECK(st.status == 200 && st.body.find("--origin-to-force-quic-on=local.hello:8443,local.admin:8192") != std::string::npos);
        CHECK(st.body.find("\"helloFallback\":true") != std::string::npos);

        f.path = L"/api/fs";
        auto drives = f.send(admin, HttpVerbGET);
        CHECK(drives.status == 200 && drives.body.find("\"parent\":null") != std::string::npos);
        f.query = L"?path=" + base;
        auto sub = f.send(admin, HttpVerbGET);
        CHECK(sub.status == 200 && sub.body.find("\"name\":\"site\"") != std::string::npos);
        f.query.clear();

        f.path = L"/api/logout";
        CHECK(f.send(admin, HttpVerbPOST).status == 200);
        f.path = L"/api/sites";
        CHECK(f.send(admin, HttpVerbGET).status == 401);
    }
    _wsystem((L"cmd /c rmdir /s /q \"" + base + L"\" >nul 2>&1").c_str());
}

static void TestCertificates() {
    std::string err;
    bool ok = certs::SelfTest("local.blog", &err);
    if (!ok) printf("  %s\n", err.c_str());
    CHECK(ok);
}

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    log::Init({false, false, L""});
    Run("util", TestUtil);
    Run("json", TestJson);
    Run("ranges", TestRanges);
    Run("conditionals", TestConditionals);
    Run("mime + alias", TestMimeAndAlias);
    Run("path sanitize (traversal corpus)", TestSanitize);
    Run("IsWithin", TestIsWithin);
    Run("containment on disk", TestContainment);
    Run("hosts block", TestHostsBlock);
    Run("config store", TestConfigStore);
    Run("certificate generation", TestCertificates);
    Run("hello page", TestHello);
    Run("http.sys over the wire", TestHttpEngine);
    Run("admin API", TestAdminApi);
    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
