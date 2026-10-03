// Content-site handlers: static files and the built-in "Hello, world!" page.
#pragma once

#include "httpsys.h"
#include "reconciler.h"

namespace wsrv {

void ServeHello(Request& req, Response& resp);
void ServeStatic(const SiteRuntime& site, const std::map<std::string, std::string>& mime, Request& req, Response& resp);
void SetErrorPage(Response& resp, int status);
// Applies the GET/HEAD-only rule. Returns false (with a 405 response) for any other verb.
bool AllowReadOnly(Request& req, Response& resp);

} // namespace wsrv
