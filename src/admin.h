// https://local.admin:8192 — embedded management UI + JSON API.
#pragma once

#include "config_store.h"
#include "httpsys.h"
#include "json.h"
#include "reconciler.h"

#include <map>
#include <mutex>
#include <string>

namespace wsrv {

class Admin {
public:
    Admin(ConfigStore& store, Reconciler& recon, std::wstring dataDirFinal);

    void Handle(Request& req, Response& resp);

    // One-time login token, valid for `ttlSeconds`.
    std::string IssueLoginToken(int64_t ttlSeconds = 120);
    static std::string LoginUrl(const std::string& token);

private:
    bool Authenticated(Request& req);
    std::string NewSession();
    void HandleApi(Request& req, Response& resp, std::wstring_view path);
    void ServeResource(Response& resp, int id, const char* contentType);

    json::Value SiteJson(const Site& s, const std::map<std::string, std::vector<std::string>>& status);
    bool SiteFromJson(const json::Value& v, Site& s, std::string& error);
    bool ValidateRoot(std::string& root, std::string& error);

    void ApiStatus(Response& resp);
    void ApiSites(Response& resp);
    void ApiCreateSite(Request& req, Response& resp);
    void ApiUpdateSite(Request& req, Response& resp, int64_t id);
    void ApiDeleteSite(Response& resp, int64_t id);
    void ApiBrowse(Request& req, Response& resp);
    void ApiSettings(Request& req, Response& resp);

    ConfigStore& store_;
    Reconciler& recon_;
    std::wstring dataDirFinal_;
    std::mutex mu_;
    std::map<std::string, int64_t> tokens_;    // one-time login tokens -> expiry
    std::map<std::string, int64_t> sessions_;  // session id -> expiry
};

} // namespace wsrv
