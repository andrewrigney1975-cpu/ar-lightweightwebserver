#include "httpsys.h"

#include "http_util.h"
#include "log.h"

#include <ws2def.h>
#include <ws2ipdef.h>

#include <cstdio>

namespace wsrv {

namespace {

constexpr ULONG kInitialBuffer = 16 * 1024;
constexpr ULONG kMaxRequestBuffer = 256 * 1024;

struct KnownHeaderName { const char* name; HTTP_HEADER_ID id; };
const KnownHeaderName kResponseHeaders[] = {
    {"cache-control", HttpHeaderCacheControl}, {"allow", HttpHeaderAllow},
    {"content-length", HttpHeaderContentLength}, {"content-type", HttpHeaderContentType},
    {"content-encoding", HttpHeaderContentEncoding}, {"content-language", HttpHeaderContentLanguage},
    {"content-location", HttpHeaderContentLocation}, {"content-range", HttpHeaderContentRange},
    {"expires", HttpHeaderExpires}, {"last-modified", HttpHeaderLastModified},
    {"accept-ranges", HttpHeaderAcceptRanges}, {"age", HttpHeaderAge}, {"etag", HttpHeaderEtag},
    {"location", HttpHeaderLocation}, {"retry-after", HttpHeaderRetryAfter}, {"server", HttpHeaderServer},
    {"set-cookie", HttpHeaderSetCookie}, {"vary", HttpHeaderVary}, {"www-authenticate", HttpHeaderWwwAuthenticate},
    {"pragma", HttpHeaderPragma},
};

int KnownResponseHeader(std::string_view name) {
    for (auto& k : kResponseHeaders)
        if (EqualsNoCase(name, k.name)) return k.id;
    return -1;
}

std::string_view PortOf(std::wstring_view host, std::string& storage) {
    size_t colon = host.rfind(L':');
    storage = colon == std::wstring_view::npos ? "443" : ToUtf8(host.substr(colon + 1));
    return storage;
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Request

std::string Request::verbName() const {
    switch (raw_->Verb) {
    case HttpVerbGET: return "GET";
    case HttpVerbHEAD: return "HEAD";
    case HttpVerbPOST: return "POST";
    case HttpVerbPUT: return "PUT";
    case HttpVerbDELETE: return "DELETE";
    case HttpVerbOPTIONS: return "OPTIONS";
    case HttpVerbTRACE: return "TRACE";
    case HttpVerbCONNECT: return "CONNECT";
    default:
        if (raw_->pUnknownVerb && raw_->UnknownVerbLength) return std::string(raw_->pUnknownVerb, raw_->UnknownVerbLength);
        return "UNKNOWN";
    }
}

std::wstring_view Request::path() const {
    auto& c = raw_->CookedUrl;
    return c.pAbsPath ? std::wstring_view(c.pAbsPath, c.AbsPathLength / sizeof(wchar_t)) : std::wstring_view(L"/");
}

std::wstring_view Request::query() const {
    auto& c = raw_->CookedUrl;
    return c.pQueryString ? std::wstring_view(c.pQueryString, c.QueryStringLength / sizeof(wchar_t)) : std::wstring_view();
}

std::wstring_view Request::host() const {
    auto& c = raw_->CookedUrl;
    return c.pHost ? std::wstring_view(c.pHost, c.HostLength / sizeof(wchar_t)) : std::wstring_view();
}

std::string Request::rawUrl() const {
    return raw_->pRawUrl ? std::string(raw_->pRawUrl, raw_->RawUrlLength) : std::string();
}

std::string Request::header(HTTP_HEADER_ID id) const {
    auto& h = raw_->Headers.KnownHeaders[id];
    return h.pRawValue ? std::string(h.pRawValue, h.RawValueLength) : std::string();
}

std::string Request::header(std::string_view name) const {
    for (USHORT i = 0; i < raw_->Headers.UnknownHeaderCount; ++i) {
        auto& u = raw_->Headers.pUnknownHeaders[i];
        if (EqualsNoCase(std::string_view(u.pName, u.NameLength), name)) return std::string(u.pRawValue, u.RawValueLength);
    }
    return {};
}

bool Request::isLoopback() const {
    const SOCKADDR* sa = raw_->Address.pRemoteAddress;
    if (!sa) return false;
    if (sa->sa_family == AF_INET) {
        auto* in = reinterpret_cast<const SOCKADDR_IN*>(sa);
        return in->sin_addr.S_un.S_un_b.s_b1 == 127;
    }
    if (sa->sa_family == AF_INET6) {
        auto* in6 = reinterpret_cast<const SOCKADDR_IN6*>(sa);
        const UCHAR* b = in6->sin6_addr.u.Byte;
        bool zero10 = true;
        for (int i = 0; i < 10; ++i) if (b[i]) zero10 = false;
        if (!zero10) return false;
        bool loop6 = b[10] == 0 && b[11] == 0 && b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 1;
        bool mapped4 = b[10] == 0xff && b[11] == 0xff && b[12] == 127;
        return loop6 || mapped4;
    }
    return false;
}

std::string Request::remoteAddress() const {
    const SOCKADDR* sa = raw_->Address.pRemoteAddress;
    char buf[64] = "-";
    if (sa && sa->sa_family == AF_INET) {
        auto& b = reinterpret_cast<const SOCKADDR_IN*>(sa)->sin_addr.S_un.S_un_b;
        snprintf(buf, sizeof buf, "%u.%u.%u.%u", b.s_b1, b.s_b2, b.s_b3, b.s_b4);
    } else if (sa && sa->sa_family == AF_INET6) {
        const UCHAR* b = reinterpret_cast<const SOCKADDR_IN6*>(sa)->sin6_addr.u.Byte;
        bool loop = true;
        for (int i = 0; i < 15; ++i) if (b[i]) loop = false;
        if (loop && b[15] == 1) return "::1";
        int n = 0;
        for (int i = 0; i < 16; i += 2) n += snprintf(buf + n, sizeof buf - n, i ? ":%x" : "%x", (b[i] << 8) | b[i + 1]);
    }
    return buf;
}

const char* Request::protocol() const {
    if (raw_->Flags & HTTP_REQUEST_FLAG_HTTP3) return "h3";
    if (raw_->Flags & HTTP_REQUEST_FLAG_HTTP2) return "h2";
    return "h1";
}

bool Request::readBody(std::string& out, size_t max) {
    out.clear();
    for (USHORT i = 0; i < raw_->EntityChunkCount; ++i) {
        auto& c = raw_->pEntityChunks[i];
        if (c.DataChunkType != HttpDataChunkFromMemory) continue;
        out.append(static_cast<const char*>(c.FromMemory.pBuffer), c.FromMemory.BufferLength);
        if (out.size() > max) return false;
    }
    if (!(raw_->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS)) return true;

    // Read the rest with a private event; the low bit stops the completion reaching the thread pool.
    UniqueHandle evt(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    char buf[8192];
    for (;;) {
        OVERLAPPED ov{};
        ResetEvent(evt.get());
        ov.hEvent = reinterpret_cast<HANDLE>(reinterpret_cast<ULONG_PTR>(evt.get()) | 1);
        ULONG r = HttpReceiveRequestEntityBody(queue_, raw_->RequestId, 0, buf, sizeof buf, nullptr, &ov);
        DWORD n = 0;
        if (r == ERROR_IO_PENDING || r == NO_ERROR) {
            if (!GetOverlappedResult(queue_, &ov, &n, TRUE)) r = GetLastError();
            else r = NO_ERROR;
        }
        if (r == ERROR_HANDLE_EOF) return true;
        if (r != NO_ERROR) return false;
        out.append(buf, n);
        if (out.size() > max) return false;
        if (n == 0) return true;
    }
}

// ---------------------------------------------------------------------------------------------
// Response

void Response::set(std::string name, std::string value) {
    for (auto& [k, v] : headers) {
        if (EqualsNoCase(k, name)) { v = std::move(value); return; }
    }
    headers.emplace_back(std::move(name), std::move(value));
}

const std::string* Response::find(std::string_view name) const {
    for (auto& [k, v] : headers) if (EqualsNoCase(k, name)) return &v;
    return nullptr;
}

// ---------------------------------------------------------------------------------------------
// HttpApiScope

HttpApiScope::HttpApiScope() {
    err_ = HttpInitialize(HTTPAPI_VERSION_2, HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG, nullptr);
    ok_ = err_ == NO_ERROR;
}

HttpApiScope::~HttpApiScope() {
    if (ok_) HttpTerminate(HTTP_INITIALIZE_SERVER | HTTP_INITIALIZE_CONFIG, nullptr);
}

// ---------------------------------------------------------------------------------------------
// HttpServer

struct HttpServer::IoContext {
    OVERLAPPED ov{};
    enum class Op { Receive, Send } op = Op::Receive;
    std::vector<BYTE> buffer;
    HTTP_REQUEST_ID requestId = HTTP_NULL_ID;

    // Response state kept alive until the send completes.
    Response response;
    HTTP_RESPONSE httpResponse{};
    std::vector<HTTP_UNKNOWN_HEADER> unknown;
    std::vector<std::string> strings;
    HTTP_DATA_CHUNK chunk{};
    std::string reason;
    std::string accessLine;

    PHTTP_REQUEST request() { return reinterpret_cast<PHTTP_REQUEST>(buffer.data()); }
};

bool HttpServer::Start(Handler handler, std::string* error) {
    handler_ = std::move(handler);
    stopping_ = false;
    auto fail = [&](const char* what, ULONG r) {
        if (error) *error = std::string(what) + ": " + ErrorTextUtf8(r);
        Stop();
        return false;
    };
    ULONG r = HttpCreateServerSession(HTTPAPI_VERSION_2, &session_, 0);
    if (r != NO_ERROR) return fail("HttpCreateServerSession", r);
    r = HttpCreateUrlGroup(session_, &group_, 0);
    if (r != NO_ERROR) return fail("HttpCreateUrlGroup", r);
    r = HttpCreateRequestQueue(HTTPAPI_VERSION_2, nullptr, nullptr, 0, &queue_);
    if (r != NO_ERROR) return fail("HttpCreateRequestQueue", r);

    HTTP_BINDING_INFO binding{};
    binding.Flags.Present = 1;
    binding.RequestQueueHandle = queue_;
    r = HttpSetUrlGroupProperty(group_, HttpServerBindingProperty, &binding, sizeof binding);
    if (r != NO_ERROR) return fail("HttpSetUrlGroupProperty", r);

    // Modest timeouts: local clients only, but don't let idle connections pile up.
    HTTP_TIMEOUT_LIMIT_INFO timeouts{};
    timeouts.Flags.Present = 1;
    timeouts.IdleConnection = 120;
    timeouts.HeaderWait = 30;
    HttpSetServerSessionProperty(session_, HttpServerTimeoutsProperty, &timeouts, sizeof timeouts);

    io_ = CreateThreadpoolIo(queue_, IoCallback, this, nullptr);
    if (!io_) return fail("CreateThreadpoolIo", GetLastError());
    drained_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int receives = (int)std::min<DWORD>(32, std::max<DWORD>(4, si.dwNumberOfProcessors * 2));
    for (int i = 0; i < receives; ++i) {
        auto* ctx = new IoContext();
        ctx->buffer.resize(kInitialBuffer);
        ++outstanding_;
        PostReceive(ctx);
    }
    return true;
}

void HttpServer::Stop() {
    stopping_ = true;
    if (queue_) {
        HttpShutdownRequestQueue(queue_);
        if (outstanding_ > 0 && drained_) WaitForSingleObject(drained_, 10000);
    }
    if (io_) {
        WaitForThreadpoolIoCallbacks(io_, FALSE);
        CloseThreadpoolIo(io_);
        io_ = nullptr;
    }
    if (group_ != HTTP_NULL_ID) { HttpCloseUrlGroup(group_); group_ = HTTP_NULL_ID; }
    if (queue_) { HttpCloseRequestQueue(queue_); queue_ = nullptr; }
    if (session_ != HTTP_NULL_ID) { HttpCloseServerSession(session_); session_ = HTTP_NULL_ID; }
    if (drained_) { CloseHandle(drained_); drained_ = nullptr; }
    std::lock_guard lk(urlMu_);
    urls_.clear();
}

DWORD HttpServer::AddUrl(const std::wstring& url, ULONGLONG context) {
    std::lock_guard lk(urlMu_);
    auto it = urls_.find(url);
    if (it != urls_.end()) {
        if (it->second == context) return NO_ERROR;
        HttpRemoveUrlFromUrlGroup(group_, url.c_str(), 0);
        urls_.erase(it);
    }
    ULONG r = HttpAddUrlToUrlGroup(group_, url.c_str(), context, 0);
    if (r == NO_ERROR) urls_[url] = context;
    return r;
}

DWORD HttpServer::RemoveUrl(const std::wstring& url) {
    std::lock_guard lk(urlMu_);
    if (!urls_.erase(url)) return NO_ERROR;
    return HttpRemoveUrlFromUrlGroup(group_, url.c_str(), 0);
}

std::map<std::wstring, ULONGLONG> HttpServer::Urls() {
    std::lock_guard lk(urlMu_);
    return urls_;
}

void HttpServer::Release(IoContext* ctx) {
    delete ctx;
    if (--outstanding_ == 0 && stopping_ && drained_) SetEvent(drained_);
}

void HttpServer::PostReceive(IoContext* ctx) {
    for (;;) {
        if (stopping_) { Release(ctx); return; }
        ctx->op = IoContext::Op::Receive;
        ctx->response = Response();
        ctx->ov = OVERLAPPED{};
        StartThreadpoolIo(io_);
        ULONG r = HttpReceiveHttpRequest(queue_, ctx->requestId, HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
                                         ctx->request(), (ULONG)ctx->buffer.size(), nullptr, &ctx->ov);
        if (r == ERROR_IO_PENDING || r == NO_ERROR) return;  // completion arrives via IoCallback
        CancelThreadpoolIo(io_);
        if (r == ERROR_CONNECTION_INVALID && ctx->requestId != HTTP_NULL_ID) {
            ctx->requestId = HTTP_NULL_ID;  // client vanished while we grew the buffer
            continue;
        }
        if (!stopping_) log::Error("HttpReceiveHttpRequest failed: " + ErrorTextUtf8(r));
        Release(ctx);
        return;
    }
}

void CALLBACK HttpServer::IoCallback(PTP_CALLBACK_INSTANCE, PVOID self, PVOID overlapped, ULONG result,
                                     ULONG_PTR bytes, PTP_IO) {
    auto* server = static_cast<HttpServer*>(self);
    auto* ctx = CONTAINING_RECORD(static_cast<OVERLAPPED*>(overlapped), IoContext, ov);
    if (ctx->op == IoContext::Op::Receive) server->OnReceive(ctx, result, bytes);
    else server->OnSend(ctx, result);
}

void HttpServer::OnReceive(IoContext* ctx, ULONG result, ULONG_PTR bytes) {
    if (result == ERROR_MORE_DATA) {
        ctx->requestId = ctx->request()->RequestId;
        if (bytes > kMaxRequestBuffer) {
            HttpCancelHttpRequest(queue_, ctx->requestId, nullptr);
            ctx->requestId = HTTP_NULL_ID;
        } else {
            ctx->buffer.resize(bytes);
        }
        PostReceive(ctx);
        return;
    }
    if (result != NO_ERROR) {
        ctx->requestId = HTTP_NULL_ID;
        if (stopping_ || result == ERROR_OPERATION_ABORTED) { Release(ctx); return; }
        PostReceive(ctx);
        return;
    }
    ctx->requestId = ctx->request()->RequestId;
    Process(ctx);
}

void HttpServer::Process(IoContext* ctx) {
    Request req(queue_, ctx->request());
    Response& resp = ctx->response;
    if (!req.isLoopback()) {
        // Local access only: refuse and drop the connection.
        resp.status = 403;
        resp.body = "Forbidden";
        resp.disconnect = true;
    } else {
        try {
            handler_(req, resp);
        } catch (const std::exception& e) {
            log::Error(std::string("Handler exception: ") + e.what());
            resp = Response();
            resp.status = 500;
            resp.body = "Internal Server Error";
        }
    }
    if (!resp.find("Server")) resp.set("Server", "wsrv");
    if (!req.isHttp3() && !resp.disconnect) {
        std::string portStorage;
        resp.set("Alt-Svc", "h3=\":" + std::string(PortOf(req.host(), portStorage)) + "\"; ma=86400");
    }
    if (log::AccessLogEnabled()) {
        uint64_t len = resp.file.valid() ? resp.fileLength : resp.body.size();
        char buf[64];
        snprintf(buf, sizeof buf, " %d %llu ", resp.status, (unsigned long long)(resp.sendBody ? len : 0));
        ctx->accessLine = FormatHttpDate(NowUnix()) + " " + req.remoteAddress() + " " + req.protocol() + " " +
                          ToUtf8(req.host()) + " \"" + req.verbName() + " " + req.rawUrl() + "\"" + buf;
        log::Access(ctx->accessLine);
    }
    SendResponse(ctx);
}

void HttpServer::SendResponse(IoContext* ctx) {
    Response& resp = ctx->response;
    HTTP_RESPONSE& hr = ctx->httpResponse;
    hr = HTTP_RESPONSE{};
    ctx->unknown.clear();
    ctx->strings.clear();

    bool bodyless = resp.status == 204 || resp.status == 304 || (resp.status >= 100 && resp.status < 200);
    uint64_t length = resp.file.valid() ? resp.fileLength : resp.body.size();
    if (!bodyless) resp.set("Content-Length", std::to_string(length));

    ctx->reason = ReasonPhrase(resp.status);
    hr.StatusCode = USHORT(resp.status);
    hr.pReason = ctx->reason.c_str();
    hr.ReasonLength = USHORT(ctx->reason.size());

    // Keep header strings stable in memory: reserve first so pointers stay valid.
    ctx->strings.reserve(resp.headers.size() * 2);
    ctx->unknown.reserve(resp.headers.size());
    for (auto& [name, value] : resp.headers) {
        int id = KnownResponseHeader(name);
        ctx->strings.push_back(value);
        const std::string& v = ctx->strings.back();
        if (id >= 0) {
            hr.Headers.KnownHeaders[id].pRawValue = v.c_str();
            hr.Headers.KnownHeaders[id].RawValueLength = USHORT(v.size());
        } else {
            ctx->strings.push_back(name);
            const std::string& n = ctx->strings.back();
            HTTP_UNKNOWN_HEADER u{};
            u.pName = n.c_str();
            u.NameLength = USHORT(n.size());
            u.pRawValue = v.c_str();
            u.RawValueLength = USHORT(v.size());
            ctx->unknown.push_back(u);
        }
    }
    hr.Headers.UnknownHeaderCount = USHORT(ctx->unknown.size());
    hr.Headers.pUnknownHeaders = ctx->unknown.empty() ? nullptr : ctx->unknown.data();

    if (!bodyless && resp.sendBody && length > 0) {
        ctx->chunk = HTTP_DATA_CHUNK{};
        if (resp.file.valid()) {
            ctx->chunk.DataChunkType = HttpDataChunkFromFileHandle;
            ctx->chunk.FromFileHandle.FileHandle = resp.file.get();
            ctx->chunk.FromFileHandle.ByteRange.StartingOffset.QuadPart = resp.fileOffset;
            ctx->chunk.FromFileHandle.ByteRange.Length.QuadPart = resp.fileLength;
        } else {
            ctx->chunk.DataChunkType = HttpDataChunkFromMemory;
            ctx->chunk.FromMemory.pBuffer = resp.body.data();
            ctx->chunk.FromMemory.BufferLength = ULONG(resp.body.size());
        }
        hr.EntityChunkCount = 1;
        hr.pEntityChunks = &ctx->chunk;
    }

    ULONG flags = resp.disconnect ? HTTP_SEND_RESPONSE_FLAG_DISCONNECT : 0;
    ctx->op = IoContext::Op::Send;
    ctx->ov = OVERLAPPED{};
    StartThreadpoolIo(io_);
    ULONG r = HttpSendHttpResponse(queue_, ctx->requestId, flags, &hr, nullptr, nullptr, nullptr, 0, &ctx->ov, nullptr);
    if (r != NO_ERROR && r != ERROR_IO_PENDING) {
        CancelThreadpoolIo(io_);
        OnSend(ctx, r);
    }
}

void HttpServer::OnSend(IoContext* ctx, ULONG result) {
    if (result != NO_ERROR && result != ERROR_CONNECTION_INVALID && result != ERROR_NETNAME_DELETED &&
        result != ERROR_OPERATION_ABORTED && !stopping_)
        log::Warn("HttpSendHttpResponse: " + ErrorTextUtf8(result));
    ctx->response.file.reset();
    ctx->requestId = HTTP_NULL_ID;
    if (ctx->buffer.size() > kInitialBuffer) {
        ctx->buffer.resize(kInitialBuffer);
        ctx->buffer.shrink_to_fit();
    }
    PostReceive(ctx);
}

} // namespace wsrv
