// Local named pipe that hands one-time admin login tokens to the owner (`wsrv open-admin`).
#pragma once

#include "util.h"

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace wsrv {

constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\wsrv-admin";

class PipeServer {
public:
    ~PipeServer() { Stop(); }
    // ownerSid may be empty (then only SYSTEM and Administrators may connect).
    bool Start(std::function<std::string()> issueToken, const std::wstring& ownerSid, std::string* error);
    void Stop();

private:
    void Run();

    std::function<std::string()> issue_;
    std::wstring sddl_;
    UniqueHandle stop_;
    std::thread thread_;
};

// Client side: fetches a token, verifying the pipe server is a genuine wsrv.exe.
bool RequestLoginToken(std::string& token, std::string* error);

} // namespace wsrv
