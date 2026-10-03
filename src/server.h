// Owns every runtime component and wires requests to handlers.
#pragma once

#include "admin.h"
#include "config_store.h"
#include "httpsys.h"
#include "pipe.h"
#include "reconciler.h"

#include <memory>
#include <string>

namespace wsrv {

struct ServerOptions {
    std::wstring dataDir;
    std::wstring ownerSid;  // allowed to fetch admin login tokens
};

class Server {
public:
    ~Server() { Stop(); }
    bool Start(const ServerOptions& opts, std::string* error);
    void Stop();
    std::string NewLoginUrl(int64_t ttlSeconds);

private:
    void Route(Request& req, Response& resp);

    std::unique_ptr<HttpApiScope> api_;
    ConfigStore store_;
    HttpServer http_;
    std::unique_ptr<Reconciler> recon_;
    std::unique_ptr<Admin> admin_;
    PipeServer pipe_;
    PTP_TIMER renewTimer_ = nullptr;
    bool started_ = false;
};

// Creates the data directory locked down to SYSTEM + Administrators. Returns its final path.
std::wstring EnsureDataDir(const std::wstring& dir, std::string* error);

} // namespace wsrv
