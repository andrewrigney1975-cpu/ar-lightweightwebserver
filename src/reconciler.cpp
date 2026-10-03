#include "reconciler.h"

#include "certs.h"
#include "hosts_file.h"
#include "log.h"

#include <set>

namespace wsrv {

namespace {

constexpr int64_t kRenewBeforeSeconds = 30 * 86400;

} // namespace

Reconciler::Reconciler(ConfigStore& store, HttpServer* http, std::wstring dataDirFinal, bool manageMachine)
    : store_(store), http_(http), dataDirFinal_(std::move(dataDirFinal)), manageMachine_(manageMachine),
      snapshot_(std::make_shared<Snapshot>()) {}

std::wstring Reconciler::UrlFor(const std::wstring& host, int port) {
    return L"https://" + host + L":" + std::to_wstring(port) + L"/";
}

std::shared_ptr<const Snapshot> Reconciler::snapshot() const {
    std::lock_guard lk(snapMu_);
    return snapshot_;
}

std::map<std::string, std::vector<std::string>> Reconciler::status() const {
    std::lock_guard lk(snapMu_);
    return status_;
}

bool Reconciler::EnsureCert(const std::string& host, std::vector<std::string>& errors) {
    auto rec = store_.GetCert(host);
    if (rec && rec->notAfter - NowUnix() > kRenewBeforeSeconds && certs::LeafPresent(rec->leafThumb)) return true;
    if (rec) {
        log::Info("Renewing certificate for " + host);
        certs::Remove(*rec);
        store_.DeleteCert(host);
    }
    certs::Issued issued;
    std::string err;
    if (!certs::Issue(host, issued, &err)) {
        errors.push_back("Certificate: " + err);
        log::Error("Certificate for " + host + " failed: " + err);
        return false;
    }
    store_.PutCert({host, issued.leafThumb, issued.rootThumb, issued.keyName, issued.notAfter});
    return true;
}

void Reconciler::Apply() {
    std::lock_guard lk(applyMu_);
    auto sites = store_.ListSites();

    std::vector<Want> want;
    want.push_back({ToUtf8(kAdminHost), kAdminPort, kAdminContext});
    bool anyMapped = false;
    for (auto& s : sites) {
        if (!s.enabled) continue;
        want.push_back({s.host, s.port, ULONGLONG(s.id)});
        if (!s.rootPath.empty()) anyMapped = true;
    }
    if (!anyMapped) want.push_back({"localhost", 443, kHelloContext});

    StatusMap status;
    for (auto& w : want) status[Key(w.host, w.port)];

    std::set<std::string> hostsNeeded;
    for (auto& w : want) hostsNeeded.insert(w.host);
    std::map<std::string, bool> certOk;
    if (manageMachine_) ApplyMachineState(want, hostsNeeded, certOk, status);
    ApplyUrls(want, status);
    BuildSnapshot(sites, status);
}

void Reconciler::ApplyMachineState(const std::vector<Want>& want, const std::set<std::string>& hostsNeeded,
                                   std::map<std::string, bool>& certOk, StatusMap& status) {
    // 1. Certificates: one per host name.
    for (auto& h : hostsNeeded) {
        std::vector<std::string> errs;
        certOk[h] = EnsureCert(h, errs);
        for (auto& w : want)
            if (w.host == h) for (auto& e : errs) status[Key(w.host, w.port)].push_back(e);
    }
    for (auto& c : store_.ListCerts()) {
        if (hostsNeeded.count(c.host)) continue;
        certs::Remove(c);
        store_.DeleteCert(c.host);
    }

    // 2. SNI bindings.
    std::set<std::string> wantedKeys;
    for (auto& w : want) {
        wantedKeys.insert(Key(w.host, w.port));
        auto rec = store_.GetCert(w.host);
        if (!certOk[w.host] || !rec) continue;
        DWORD r = certs::BindSni(FromUtf8(w.host), w.port, rec->leafThumb);
        if (r == NO_ERROR) store_.PutBinding({w.host, w.port});
        else status[Key(w.host, w.port)].push_back("TLS binding: " + ErrorTextUtf8(r));
    }
    for (auto& b : store_.ListBindings()) {
        if (wantedKeys.count(Key(b.host, b.port))) continue;
        certs::UnbindSni(FromUtf8(b.host), b.port);
        store_.DeleteBinding(b);
    }

    // 3. Hosts file (local.* names only; localhost always resolves).
    std::vector<std::string> names;
    for (auto& h : hostsNeeded) if (h != "localhost") names.push_back(h);
    std::string hostsErr;
    if (!hosts::Update(names, &hostsErr)) {
        log::Error("Hosts file: " + hostsErr);
        for (auto& w : want) if (w.host != "localhost") status[Key(w.host, w.port)].push_back("Hosts file: " + hostsErr);
    }
}

void Reconciler::ApplyUrls(const std::vector<Want>& want, StatusMap& status) {
    if (http_) {
        std::map<std::wstring, std::pair<ULONGLONG, std::string>> desired;
        for (auto& w : want) desired[UrlFor(FromUtf8(w.host), w.port)] = {w.context, Key(w.host, w.port)};
        for (auto& [url, ctx] : http_->Urls()) {
            auto it = desired.find(url);
            if (it == desired.end() || it->second.first != ctx) http_->RemoveUrl(url);
        }
        for (auto& [url, v] : desired) {
            DWORD r = http_->AddUrl(url, v.first);
            if (r == ERROR_ALREADY_EXISTS) status[v.second].push_back("Address is already registered by another application.");
            else if (r != NO_ERROR) status[v.second].push_back("Listen: " + ErrorTextUtf8(r));
        }
    }
}

void Reconciler::BuildSnapshot(const std::vector<Site>& sites, StatusMap& status) {
    auto snap = std::make_shared<Snapshot>();
    snap->mime = store_.MimeOverrides();
    for (auto& s : sites) {
        auto rt = std::make_shared<SiteRuntime>();
        rt->site = s;
        rt->policy.serveHidden = s.serveHidden;
        rt->policy.forbiddenFinal = dataDirFinal_;
        if (!s.rootPath.empty()) {
            DWORD err = 0;
            rt->policy.rootFinal = FinalPathOfDirectory(FromUtf8(s.rootPath), &err);
            if (rt->policy.rootFinal.empty()) {
                rt->rootError = "Folder unavailable: " + ErrorTextUtf8(err);
            } else if (!dataDirFinal_.empty() &&
                       (IsWithin(rt->policy.rootFinal, dataDirFinal_) || IsWithin(dataDirFinal_, rt->policy.rootFinal))) {
                rt->rootError = "Folder overlaps wsrv's configuration directory and will not be served.";
                rt->policy.rootFinal.clear();
            }
            if (!rt->rootError.empty() && s.enabled) status[Key(s.host, s.port)].push_back(rt->rootError);
        }
        snap->sites[s.id] = rt;
    }

    for (auto& [key, errs] : status)
        for (auto& e : errs) log::Warn(key + ": " + e);

    std::lock_guard sk(snapMu_);
    snapshot_ = snap;
    status_ = std::move(status);
}

void Reconciler::RemoveAll() {
    std::lock_guard lk(applyMu_);
    for (auto& b : store_.ListBindings()) {
        certs::UnbindSni(FromUtf8(b.host), b.port);
        store_.DeleteBinding(b);
    }
    for (auto& c : store_.ListCerts()) {
        certs::Remove(c);
        store_.DeleteCert(c.host);
    }
    std::string err;
    if (!hosts::Update({}, &err)) log::Error("Hosts file: " + err);
}

} // namespace wsrv
