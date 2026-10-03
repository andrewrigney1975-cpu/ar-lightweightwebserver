// Brings the machine in line with the configuration: certificates, SNI bindings, hosts file,
// http.sys URL registrations and the in-memory routing snapshot. Idempotent; safe to call often.
#pragma once

#include "config_store.h"
#include "httpsys.h"
#include "path_guard.h"

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace wsrv {

constexpr ULONGLONG kAdminContext = 0xFFFFFFFF00000001ull;
constexpr ULONGLONG kHelloContext = 0xFFFFFFFF00000002ull;

struct SiteRuntime {
    Site site;
    GuardPolicy policy;
    std::string rootError;  // non-empty when the folder is unavailable
};

struct Snapshot {
    std::map<int64_t, std::shared_ptr<const SiteRuntime>> sites;
    std::map<std::string, std::string> mime;
};

class Reconciler {
public:
    // http may be null (uninstall path: only machine state is touched). manageMachine=false skips
    // certificates, SNI bindings and the hosts file (used by tests).
    Reconciler(ConfigStore& store, HttpServer* http, std::wstring dataDirFinal, bool manageMachine = true);

    void Apply();
    // Removes every binding, certificate and hosts entry wsrv created.
    void RemoveAll();

    std::shared_ptr<const Snapshot> snapshot() const;
    // Problems per "host:port" from the last Apply().
    std::map<std::string, std::vector<std::string>> status() const;

    static std::string Key(const std::string& host, int port) { return host + ":" + std::to_string(port); }
    static std::wstring UrlFor(const std::wstring& host, int port);

private:
    struct Want {
        std::string host;
        int port;
        ULONGLONG context;
    };
    using StatusMap = std::map<std::string, std::vector<std::string>>;

    bool EnsureCert(const std::string& host, std::vector<std::string>& errors);
    void ApplyMachineState(const std::vector<Want>& want, const std::set<std::string>& hostsNeeded,
                           std::map<std::string, bool>& certOk, StatusMap& status);
    void ApplyUrls(const std::vector<Want>& want, StatusMap& status);
    void BuildSnapshot(const std::vector<Site>& sites, StatusMap& status);

    ConfigStore& store_;
    HttpServer* http_;
    std::wstring dataDirFinal_;
    bool manageMachine_;
    std::mutex applyMu_;
    mutable std::mutex snapMu_;
    std::shared_ptr<const Snapshot> snapshot_;
    std::map<std::string, std::vector<std::string>> status_;
};

} // namespace wsrv
