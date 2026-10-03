// Maintains a wsrv-owned block in the Windows hosts file so local.* aliases resolve to loopback.
#pragma once

#include <string>
#include <vector>

namespace wsrv::hosts {

// Returns `original` with the wsrv block replaced by entries for `names` (block removed if empty).
std::string ApplyBlock(const std::string& original, const std::vector<std::string>& names);

// Reads, transforms and atomically rewrites the system hosts file (only if it changed).
bool Update(const std::vector<std::string>& names, std::string* error);

} // namespace wsrv::hosts
