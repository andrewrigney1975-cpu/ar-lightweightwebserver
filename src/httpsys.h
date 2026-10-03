// Thin, asynchronous wrapper over the HTTP Server API (http.sys).
#pragma once

#include "util.h"

#include <http.h>

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace wsrv {

class Request {
public:
    Request(HANDLE queue, PHTTP_REQUEST raw) : queue_(queue), raw_(raw) {}

    PHTTP_REQUEST raw() const { return raw_; }
    ULONGLONG context() const { return raw_->UrlContext; }
    HTTP_VERB verb() const { return raw_->Verb; }
    std::string verbName() const;
    std::wstring_view path() const;   // decoded, e.g. L"/a/b.html"
    std::wstring_view query() const;  // includes leading '?', or empty
    std::wstring_view host() const;   // "local.foo:443"
    std::string rawUrl() const;       // as sent by the client
    std::string header(HTTP_HEADER_ID id) const;
    std::string header(std::string_view name) const;  // unknown headers only
    bool isLoopback() const;
    std::string remoteAddress() const;
    const char* protocol() const;  // "h1", "h2", "h3"
    bool isHttp3() const { return (raw_->Flags & HTTP_REQUEST_FLAG_HTTP3) != 0; }
    bool hasBody() const {
        return raw_->EntityChunkCount > 0 || (raw_->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) != 0;
    }

    // Reads the entity body up to `max` bytes. Returns false if larger than max or on error.
    bool readBody(std::string& out, size_t max);

private:
    HANDLE queue_;
    PHTTP_REQUEST raw_;
};

struct Response {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    UniqueHandle file;       // when valid, the body comes from this file
    uint64_t fileOffset = 0;
    uint64_t fileLength = 0;
    bool sendBody = true;    // false for HEAD: headers (incl. Content-Length) only
    bool disconnect = false;

    void set(std::string name, std::string value);
    const std::string* find(std::string_view name) const;
};

using Handler = std::function<void(Request&, Response&)>;

class HttpServer {
public:
    HttpServer() = default;
    ~HttpServer() { Stop(); }
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    bool Start(Handler handler, std::string* error);
    void Stop();

    DWORD AddUrl(const std::wstring& url, ULONGLONG context);
    DWORD RemoveUrl(const std::wstring& url);
    std::map<std::wstring, ULONGLONG> Urls();

private:
    struct IoContext;
    static void CALLBACK IoCallback(PTP_CALLBACK_INSTANCE, PVOID ctx, PVOID overlapped, ULONG result,
                                    ULONG_PTR bytes, PTP_IO io);
    void PostReceive(IoContext* ctx);
    void OnReceive(IoContext* ctx, ULONG result, ULONG_PTR bytes);
    void OnSend(IoContext* ctx, ULONG result);
    void Process(IoContext* ctx);
    void SendResponse(IoContext* ctx);
    void Release(IoContext* ctx);

    Handler handler_;
    HTTP_SERVER_SESSION_ID session_ = HTTP_NULL_ID;
    HTTP_URL_GROUP_ID group_ = HTTP_NULL_ID;
    HANDLE queue_ = nullptr;
    PTP_IO io_ = nullptr;
    std::atomic<bool> stopping_{false};
    std::atomic<long> outstanding_{0};
    HANDLE drained_ = nullptr;
    std::mutex urlMu_;
    std::map<std::wstring, ULONGLONG> urls_;
};

// Process-wide HttpInitialize/HttpTerminate for server + configuration APIs.
class HttpApiScope {
public:
    HttpApiScope();
    ~HttpApiScope();
    bool ok() const { return ok_; }
    ULONG error() const { return err_; }
private:
    bool ok_ = false;
    ULONG err_ = 0;
};

} // namespace wsrv
