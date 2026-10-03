#include "server.h"

#include "handlers.h"
#include "log.h"
#include "path_guard.h"

#include <sddl.h>

namespace wsrv {

std::wstring EnsureDataDir(const std::wstring& dir, std::string* error) {
    if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        // Protected DACL: SYSTEM and Administrators only, inherited by the database and logs.
        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &sd, nullptr);
        SECURITY_ATTRIBUTES sa{sizeof sa, sd, FALSE};
        BOOL ok = CreateDirectoryW(dir.c_str(), &sa);
        DWORD err = GetLastError();
        LocalFree(sd);
        if (!ok && err != ERROR_ALREADY_EXISTS) {
            if (error) *error = "Cannot create " + ToUtf8(dir) + ": " + ErrorTextUtf8(err);
            return {};
        }
    }
    DWORD err = 0;
    std::wstring finalPath = FinalPathOfDirectory(dir, &err);
    if (finalPath.empty() && error) *error = "Cannot open " + ToUtf8(dir) + ": " + ErrorTextUtf8(err);
    return finalPath;
}

bool Server::Start(const ServerOptions& opts, std::string* error) {
    std::wstring dataFinal = EnsureDataDir(opts.dataDir, error);
    if (dataFinal.empty()) return false;

    api_ = std::make_unique<HttpApiScope>();
    if (!api_->ok()) {
        if (error) *error = "HttpInitialize: " + ErrorTextUtf8(api_->error());
        return false;
    }
    if (!store_.Open(opts.dataDir + L"\\wsrv.db", error)) return false;
    log::SetAccessLog(store_.GetSetting("access_log").value_or("0") == "1");

    if (!http_.Start([this](Request& q, Response& r) { Route(q, r); }, error)) return false;

    recon_ = std::make_unique<Reconciler>(store_, &http_, dataFinal);
    admin_ = std::make_unique<Admin>(store_, *recon_, dataFinal);
    recon_->Apply();

    std::wstring owner = opts.ownerSid;
    if (owner.empty()) owner = FromUtf8(store_.GetSetting("owner_sid").value_or(""));
    std::string pipeErr;
    if (!pipe_.Start([this] { return admin_->IssueLoginToken(); }, owner, &pipeErr))
        log::Warn("Admin pipe unavailable: " + pipeErr);

    // Daily maintenance: renews certificates nearing expiry and re-checks site folders.
    renewTimer_ = CreateThreadpoolTimer(
        [](PTP_CALLBACK_INSTANCE, PVOID self, PTP_TIMER) { static_cast<Server*>(self)->recon_->Apply(); }, this, nullptr);
    if (renewTimer_) {
        ULARGE_INTEGER due;
        due.QuadPart = ULONGLONG(-(24LL * 3600 * 10000000));
        FILETIME ft{due.LowPart, due.HighPart};
        SetThreadpoolTimer(renewTimer_, &ft, 24 * 3600 * 1000, 60 * 1000);
    }

    switch (QueryHttpFeature(L"EnableHttp3")) {
    case HttpFeatureState::Disabled:
        log::Warn("HTTP/3 is disabled in http.sys (EnableHttp3). Run 'wsrv install' and reboot to enable it. Serving HTTP/2.");
        break;
    case HttpFeatureState::PendingRestart:
        log::Warn("HTTP/3 was turned on in http.sys after Windows started; it takes effect after a reboot. Serving HTTP/2.");
        break;
    default: break;
    }
    started_ = true;
    log::Info(std::string("wsrv ") + kVersion + " started; admin at https://local.admin:8192/");
    return true;
}

void Server::Stop() {
    if (renewTimer_) {
        SetThreadpoolTimer(renewTimer_, nullptr, 0, 0);
        WaitForThreadpoolTimerCallbacks(renewTimer_, TRUE);
        CloseThreadpoolTimer(renewTimer_);
        renewTimer_ = nullptr;
    }
    pipe_.Stop();
    http_.Stop();
    admin_.reset();
    recon_.reset();
    store_.Close();
    api_.reset();
    if (started_) log::Info("wsrv stopped");
    started_ = false;
}

std::string Server::NewLoginUrl(int64_t ttl) { return Admin::LoginUrl(admin_->IssueLoginToken(ttl)); }

void Server::Route(Request& req, Response& resp) {
    ULONGLONG ctx = req.context();
    if (ctx == kAdminContext) { admin_->Handle(req, resp); return; }
    if (ctx == kHelloContext) { ServeHello(req, resp); return; }

    auto snap = recon_->snapshot();
    auto it = snap->sites.find(int64_t(ctx));
    if (it == snap->sites.end() || !it->second->site.enabled) {
        if (!AllowReadOnly(req, resp)) return;
        SetErrorPage(resp, 404);
        return;
    }
    const SiteRuntime& site = *it->second;
    if (site.site.rootPath.empty()) { ServeHello(req, resp); return; }
    ServeStatic(site, snap->mime, req, resp);
}

} // namespace wsrv
