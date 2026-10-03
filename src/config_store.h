// SQLite-backed configuration. Thread-safe (one connection guarded by a mutex).
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace wsrv {

struct Site {
    int64_t id = 0;
    std::string name;
    std::string host;      // "local.foo"
    int port = 443;
    std::string rootPath;  // UTF-8 folder path; empty = no folder mapped (hello page)
    bool enabled = true;
    bool dirListing = false;
    bool serveHidden = false;
    std::string cacheControl = "no-cache";
};

struct CertRecord {
    std::string host;
    std::string leafThumb;  // hex SHA-1
    std::string rootThumb;  // hex SHA-1
    std::string keyName;    // CNG machine key container
    int64_t notAfter = 0;   // unix seconds
};

struct BindingRecord {
    std::string host;
    int port = 0;
};

class ConfigStore {
public:
    ConfigStore() = default;
    ~ConfigStore();
    ConfigStore(const ConfigStore&) = delete;
    ConfigStore& operator=(const ConfigStore&) = delete;

    bool Open(const std::wstring& path, std::string* error);
    void Close();

    std::vector<Site> ListSites();
    std::optional<Site> GetSite(int64_t id);
    // Returns false and sets error (e.g. duplicate host:port). On insert, site.id is filled in.
    bool InsertSite(Site& site, std::string* error);
    bool UpdateSite(const Site& site, std::string* error);
    bool DeleteSite(int64_t id);

    std::optional<std::string> GetSetting(const std::string& key);
    void SetSetting(const std::string& key, const std::string& value);

    std::vector<CertRecord> ListCerts();
    std::optional<CertRecord> GetCert(const std::string& host);
    void PutCert(const CertRecord& rec);
    void DeleteCert(const std::string& host);

    std::vector<BindingRecord> ListBindings();
    void PutBinding(const BindingRecord& rec);
    void DeleteBinding(const BindingRecord& rec);

    std::map<std::string, std::string> MimeOverrides();

private:
    bool Migrate(std::string* error);
    bool Exec(const char* sql, std::string* error = nullptr);

    std::recursive_mutex mu_;
    sqlite3* db_ = nullptr;
};

} // namespace wsrv
