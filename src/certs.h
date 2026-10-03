// Locally-trusted TLS certificates and http.sys SNI bindings.
//
// For each host wsrv creates a single-use root CA, signs one leaf certificate with it and then
// destroys the CA private key. The root goes into LocalMachine\Root, the leaf (with a persisted,
// non-exportable machine key) into LocalMachine\My. A stolen root can't sign anything new.
#pragma once

#include "config_store.h"
#include "util.h"

#include <string>

namespace wsrv::certs {

struct Issued {
    std::string leafThumb;
    std::string rootThumb;
    std::string keyName;
    int64_t notAfter = 0;
};

// Requires elevation (machine key + LocalMachine stores).
bool Issue(const std::string& host, Issued& out, std::string* error);
// True when the leaf certificate is present in LocalMachine\My.
bool LeafPresent(const std::string& leafThumbHex);
// Removes leaf, root and the private key. Best effort.
void Remove(const CertRecord& rec);

// Builds a certificate pair with ephemeral keys and verifies the chain signature, SAN and EKU.
// Touches no certificate stores — used by the unit tests.
bool SelfTest(const std::string& host, std::string* error);

// http.sys SNI binding for host:port -> leaf certificate. Requires elevation.
DWORD BindSni(const std::wstring& host, int port, const std::string& leafThumbHex);
DWORD UnbindSni(const std::wstring& host, int port);

} // namespace wsrv::certs
