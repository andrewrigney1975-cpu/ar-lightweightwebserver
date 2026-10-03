// Minimal logger: console (foreground mode), rolling file, and Windows Event Log for warnings/errors.
#pragma once

#include <string>
#include <string_view>

namespace wsrv::log {

enum class Level { Info, Warn, Error };

struct Options {
    bool console = false;
    bool eventLog = false;
    std::wstring dir;  // empty = no file logging
};

void Init(const Options& opts);
void Shutdown();
void SetAccessLog(bool enabled);
bool AccessLogEnabled();

void Write(Level level, std::string_view msg);
inline void Info(std::string_view m) { Write(Level::Info, m); }
inline void Warn(std::string_view m) { Write(Level::Warn, m); }
inline void Error(std::string_view m) { Write(Level::Error, m); }

void Access(std::string_view line);

} // namespace wsrv::log
