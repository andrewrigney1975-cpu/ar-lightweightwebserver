#include "config_store.h"

#include "util.h"

#include "../third_party/sqlite/sqlite3.h"

namespace wsrv {

namespace {

// Thin RAII wrapper around a prepared statement.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) { sqlite3_prepare_v2(db, sql, -1, &s_, nullptr); }
    ~Stmt() { sqlite3_finalize(s_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    bool ok() const { return s_ != nullptr; }
    Stmt& bind(int i, const std::string& v) { sqlite3_bind_text(s_, i, v.c_str(), (int)v.size(), SQLITE_TRANSIENT); return *this; }
    Stmt& bind(int i, int64_t v) { sqlite3_bind_int64(s_, i, v); return *this; }
    Stmt& bindNull(int i) { sqlite3_bind_null(s_, i); return *this; }
    int step() { return s_ ? sqlite3_step(s_) : SQLITE_ERROR; }
    bool row() { return step() == SQLITE_ROW; }
    std::string text(int col) {
        auto p = reinterpret_cast<const char*>(sqlite3_column_text(s_, col));
        return p ? std::string(p, sqlite3_column_bytes(s_, col)) : std::string();
    }
    int64_t i64(int col) { return sqlite3_column_int64(s_, col); }
    bool isNull(int col) { return sqlite3_column_type(s_, col) == SQLITE_NULL; }

private:
    sqlite3_stmt* s_ = nullptr;
};

constexpr const char* kSiteColumns =
    "id, name, host, port, root_path, enabled, dir_listing, serve_hidden, cache_control";

Site ReadSite(Stmt& st) {
    Site s;
    s.id = st.i64(0);
    s.name = st.text(1);
    s.host = st.text(2);
    s.port = (int)st.i64(3);
    s.rootPath = st.isNull(4) ? std::string() : st.text(4);
    s.enabled = st.i64(5) != 0;
    s.dirListing = st.i64(6) != 0;
    s.serveHidden = st.i64(7) != 0;
    s.cacheControl = st.text(8);
    return s;
}

void BindSite(Stmt& st, const Site& s) {
    st.bind(1, s.name).bind(2, s.host).bind(3, int64_t(s.port));
    if (s.rootPath.empty()) st.bindNull(4); else st.bind(4, s.rootPath);
    st.bind(5, int64_t(s.enabled)).bind(6, int64_t(s.dirListing)).bind(7, int64_t(s.serveHidden));
    st.bind(8, s.cacheControl);
}

} // namespace

ConfigStore::~ConfigStore() { Close(); }

void ConfigStore::Close() {
    std::lock_guard lk(mu_);
    if (db_) sqlite3_close(db_);
    db_ = nullptr;
}

bool ConfigStore::Exec(const char* sql, std::string* error) {
    char* msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &msg);
    if (rc != SQLITE_OK && error) *error = msg ? msg : "sqlite error";
    sqlite3_free(msg);
    return rc == SQLITE_OK;
}

bool ConfigStore::Open(const std::wstring& path, std::string* error) {
    std::lock_guard lk(mu_);
    std::string p = ToUtf8(path);
    int rc = sqlite3_open_v2(p.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        if (error) *error = db_ ? sqlite3_errmsg(db_) : "cannot open database";
        Close();
        return false;
    }
    sqlite3_busy_timeout(db_, 5000);
    Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;");
    return Migrate(error);
}

bool ConfigStore::Migrate(std::string* error) {
    int64_t version = 0;
    {
        Stmt st(db_, "PRAGMA user_version");
        if (st.row()) version = st.i64(0);
    }
    if (version < 1) {
        const char* v1 = R"sql(
BEGIN;
CREATE TABLE sites(
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL,
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
  root_path     TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  dir_listing   INTEGER NOT NULL DEFAULT 0,
  serve_hidden  INTEGER NOT NULL DEFAULT 0,
  cache_control TEXT NOT NULL DEFAULT 'no-cache',
  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE(host, port)
);
CREATE TABLE certs(
  host       TEXT PRIMARY KEY,
  leaf_thumb TEXT NOT NULL,
  root_thumb TEXT NOT NULL,
  key_name   TEXT NOT NULL,
  not_after  INTEGER NOT NULL
);
CREATE TABLE bindings(
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  PRIMARY KEY(host, port)
);
CREATE TABLE mime_types(
  ext          TEXT PRIMARY KEY,
  content_type TEXT NOT NULL
);
CREATE TABLE settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
PRAGMA user_version = 1;
COMMIT;
)sql";
        if (!Exec(v1, error)) { Exec("ROLLBACK"); return false; }
    }
    return true;
}

std::vector<Site> ConfigStore::ListSites() {
    std::lock_guard lk(mu_);
    std::vector<Site> out;
    Stmt st(db_, (std::string("SELECT ") + kSiteColumns + " FROM sites ORDER BY host, port").c_str());
    while (st.row()) out.push_back(ReadSite(st));
    return out;
}

std::optional<Site> ConfigStore::GetSite(int64_t id) {
    std::lock_guard lk(mu_);
    Stmt st(db_, (std::string("SELECT ") + kSiteColumns + " FROM sites WHERE id = ?1").c_str());
    st.bind(1, id);
    if (st.row()) return ReadSite(st);
    return std::nullopt;
}

static std::string ConstraintMessage(sqlite3* db) {
    std::string m = sqlite3_errmsg(db);
    if (m.find("UNIQUE") != std::string::npos) return "Another site already uses this alias and port.";
    return m;
}

bool ConfigStore::InsertSite(Site& s, std::string* error) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "INSERT INTO sites(name, host, port, root_path, enabled, dir_listing, serve_hidden, cache_control) "
                 "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
    BindSite(st, s);
    if (st.step() != SQLITE_DONE) { if (error) *error = ConstraintMessage(db_); return false; }
    s.id = sqlite3_last_insert_rowid(db_);
    return true;
}

bool ConfigStore::UpdateSite(const Site& s, std::string* error) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "UPDATE sites SET name=?1, host=?2, port=?3, root_path=?4, enabled=?5, dir_listing=?6, "
                 "serve_hidden=?7, cache_control=?8, updated_at=unixepoch() WHERE id=?9");
    BindSite(st, s);
    st.bind(9, s.id);
    if (st.step() != SQLITE_DONE) { if (error) *error = ConstraintMessage(db_); return false; }
    if (sqlite3_changes(db_) == 0) { if (error) *error = "Site not found."; return false; }
    return true;
}

bool ConfigStore::DeleteSite(int64_t id) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "DELETE FROM sites WHERE id=?1");
    st.bind(1, id);
    return st.step() == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::optional<std::string> ConfigStore::GetSetting(const std::string& key) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "SELECT value FROM settings WHERE key=?1");
    st.bind(1, key);
    if (st.row()) return st.text(0);
    return std::nullopt;
}

void ConfigStore::SetSetting(const std::string& key, const std::string& value) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "INSERT INTO settings(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
    st.bind(1, key).bind(2, value);
    st.step();
}

std::vector<CertRecord> ConfigStore::ListCerts() {
    std::lock_guard lk(mu_);
    std::vector<CertRecord> out;
    Stmt st(db_, "SELECT host, leaf_thumb, root_thumb, key_name, not_after FROM certs");
    while (st.row()) out.push_back({st.text(0), st.text(1), st.text(2), st.text(3), st.i64(4)});
    return out;
}

std::optional<CertRecord> ConfigStore::GetCert(const std::string& host) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "SELECT host, leaf_thumb, root_thumb, key_name, not_after FROM certs WHERE host=?1");
    st.bind(1, host);
    if (st.row()) return CertRecord{st.text(0), st.text(1), st.text(2), st.text(3), st.i64(4)};
    return std::nullopt;
}

void ConfigStore::PutCert(const CertRecord& r) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "INSERT OR REPLACE INTO certs(host, leaf_thumb, root_thumb, key_name, not_after) VALUES(?1,?2,?3,?4,?5)");
    st.bind(1, r.host).bind(2, r.leafThumb).bind(3, r.rootThumb).bind(4, r.keyName).bind(5, r.notAfter);
    st.step();
}

void ConfigStore::DeleteCert(const std::string& host) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "DELETE FROM certs WHERE host=?1");
    st.bind(1, host);
    st.step();
}

std::vector<BindingRecord> ConfigStore::ListBindings() {
    std::lock_guard lk(mu_);
    std::vector<BindingRecord> out;
    Stmt st(db_, "SELECT host, port FROM bindings");
    while (st.row()) out.push_back({st.text(0), (int)st.i64(1)});
    return out;
}

void ConfigStore::PutBinding(const BindingRecord& r) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "INSERT OR IGNORE INTO bindings(host, port) VALUES(?1, ?2)");
    st.bind(1, r.host).bind(2, int64_t(r.port));
    st.step();
}

void ConfigStore::DeleteBinding(const BindingRecord& r) {
    std::lock_guard lk(mu_);
    Stmt st(db_, "DELETE FROM bindings WHERE host=?1 AND port=?2");
    st.bind(1, r.host).bind(2, int64_t(r.port));
    st.step();
}

std::map<std::string, std::string> ConfigStore::MimeOverrides() {
    std::lock_guard lk(mu_);
    std::map<std::string, std::string> out;
    Stmt st(db_, "SELECT ext, content_type FROM mime_types");
    while (st.row()) out[ToLowerAscii(st.text(0))] = st.text(1);
    return out;
}

} // namespace wsrv
