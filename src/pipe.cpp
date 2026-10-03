#include "pipe.h"

#include "log.h"

#include <sddl.h>

namespace wsrv {

namespace {

constexpr DWORD kIoTimeoutMs = 3000;

// Waits for an overlapped operation, giving up on timeout or stop.
bool WaitIo(HANDLE h, OVERLAPPED& ov, HANDLE stop, DWORD& bytes) {
    HANDLE waits[2] = {ov.hEvent, stop};
    DWORD r = WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, kIoTimeoutMs);
    if (r != WAIT_OBJECT_0) {
        CancelIoEx(h, &ov);
        GetOverlappedResult(h, &ov, &bytes, TRUE);
        return false;
    }
    return GetOverlappedResult(h, &ov, &bytes, FALSE) != FALSE;
}

std::wstring ServiceBinaryPath() {
    std::wstring out;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return out;
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_QUERY_CONFIG);
    if (svc) {
        DWORD needed = 0;
        QueryServiceConfigW(svc, nullptr, 0, &needed);
        std::vector<BYTE> buf(needed);
        auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (needed && QueryServiceConfigW(svc, cfg, needed, &needed)) {
            std::wstring p = cfg->lpBinaryPathName;
            if (!p.empty() && p.front() == L'"') {
                size_t end = p.find(L'"', 1);
                out = p.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
            } else {
                out = p.substr(0, p.find(L' '));
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return out;
}

DWORD ServiceProcessId() {
    DWORD pid = 0;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS_PROCESS st{};
        DWORD n = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&st), sizeof st, &n) &&
            st.dwCurrentState == SERVICE_RUNNING)
            pid = st.dwProcessId;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return pid;
}

} // namespace

bool PipeServer::Start(std::function<std::string()> issueToken, const std::wstring& ownerSid, std::string* error) {
    issue_ = std::move(issueToken);
    sddl_ = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    if (!ownerSid.empty()) sddl_ += L"(A;;GRGW;;;" + ownerSid + L")";
    stop_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop_.valid()) { if (error) *error = ErrorTextUtf8(GetLastError()); return false; }
    thread_ = std::thread([this] { Run(); });
    return true;
}

void PipeServer::Stop() {
    if (stop_.valid()) SetEvent(stop_.get());
    if (thread_.joinable()) thread_.join();
    stop_.reset();
}

void PipeServer::Run() {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        log::Error("Admin pipe: bad security descriptor: " + ErrorTextUtf8(GetLastError()));
        return;
    }
    SECURITY_ATTRIBUTES sa{sizeof sa, sd, FALSE};
    UniqueHandle evt(CreateEventW(nullptr, TRUE, FALSE, nullptr));

    while (WaitForSingleObject(stop_.get(), 0) != WAIT_OBJECT_0) {
        UniqueHandle pipe(CreateNamedPipeW(kPipeName,
                                           PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                           PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                           1, 512, 512, 0, &sa));
        if (!pipe.valid()) {
            log::Error("Admin pipe: " + ErrorTextUtf8(GetLastError()));
            if (WaitForSingleObject(stop_.get(), 5000) == WAIT_OBJECT_0) break;
            continue;
        }
        OVERLAPPED ov{};
        ov.hEvent = evt.get();
        ResetEvent(evt.get());
        BOOL connected = ConnectNamedPipe(pipe.get(), &ov);
        DWORD err = connected ? ERROR_PIPE_CONNECTED : GetLastError();
        if (err == ERROR_IO_PENDING) {
            HANDLE waits[2] = {evt.get(), stop_.get()};
            if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0) {
                CancelIoEx(pipe.get(), &ov);
                break;
            }
            DWORD n = 0;
            err = GetOverlappedResult(pipe.get(), &ov, &n, FALSE) ? ERROR_PIPE_CONNECTED : GetLastError();
        }
        if (err != ERROR_PIPE_CONNECTED) continue;

        char req[64];
        DWORD n = 0;
        ov = OVERLAPPED{};
        ov.hEvent = evt.get();
        ResetEvent(evt.get());
        if (!ReadFile(pipe.get(), req, sizeof req, nullptr, &ov) && GetLastError() != ERROR_IO_PENDING) continue;
        if (!WaitIo(pipe.get(), ov, stop_.get(), n)) continue;
        if (std::string_view(req, n) != "token") continue;

        std::string token = issue_();
        ov = OVERLAPPED{};
        ov.hEvent = evt.get();
        ResetEvent(evt.get());
        if (WriteFile(pipe.get(), token.data(), (DWORD)token.size(), nullptr, &ov) || GetLastError() == ERROR_IO_PENDING)
            WaitIo(pipe.get(), ov, stop_.get(), n);
        FlushFileBuffers(pipe.get());
        DisconnectNamedPipe(pipe.get());
    }
    LocalFree(sd);
}

bool RequestLoginToken(std::string& token, std::string* error) {
    if (!WaitNamedPipeW(kPipeName, 5000)) {
        if (error) *error = "wsrv is not running (no admin pipe). Start the service or run 'wsrv run'.";
        return false;
    }
    UniqueHandle h(CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (!h.valid()) {
        DWORD e = GetLastError();
        if (error)
            *error = e == ERROR_ACCESS_DENIED ? "Access denied: only the wsrv owner and Administrators may open the admin site."
                                              : "Cannot connect to wsrv: " + ErrorTextUtf8(e);
        return false;
    }

    // Make sure we are talking to wsrv itself, not a process squatting on the pipe name.
    ULONG pid = 0;
    std::wstring serverImage;
    if (GetNamedPipeServerProcessId(h.get(), &pid)) {
        UniqueHandle proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (proc.valid()) {
            wchar_t buf[MAX_PATH * 2];
            DWORD len = ARRAYSIZE(buf);
            if (QueryFullProcessImageNameW(proc.get(), 0, buf, &len)) serverImage.assign(buf, len);
        }
    }
    std::wstring svcPath = ServiceBinaryPath();
    bool genuine = !serverImage.empty() &&
                   (EqualsNoCase(serverImage, ExePath()) || (!svcPath.empty() && EqualsNoCase(serverImage, svcPath)));
    if (!genuine && pid) genuine = pid == ServiceProcessId();
    if (!genuine) {
        if (error) *error = "The admin pipe is not owned by wsrv.exe; refusing to continue.";
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h.get(), &mode, nullptr, nullptr);
    DWORD n = 0;
    if (!WriteFile(h.get(), "token", 5, &n, nullptr)) {
        if (error) *error = "Pipe write failed: " + ErrorTextUtf8(GetLastError());
        return false;
    }
    char buf[256];
    if (!ReadFile(h.get(), buf, sizeof buf, &n, nullptr) || n == 0) {
        if (error) *error = "Pipe read failed: " + ErrorTextUtf8(GetLastError());
        return false;
    }
    token.assign(buf, n);
    for (char c : token)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            if (error) *error = "Malformed token from wsrv.";
            return false;
        }
    return true;
}

} // namespace wsrv
