#include "certs.h"

#include "log.h"
#include "util.h"

#include <http.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <ws2def.h>

#include <memory>
#include <vector>

namespace wsrv::certs {

namespace {

constexpr int64_t kLeafLifetimeDays = 397;
// {6f1e0c8a-3b5d-4e2f-9a71-5c0d2b8e7f14}
constexpr GUID kAppId = {0x6f1e0c8a, 0x3b5d, 0x4e2f, {0x9a, 0x71, 0x5c, 0x0d, 0x2b, 0x8e, 0x7f, 0x14}};

struct NKey {
    NCRYPT_KEY_HANDLE h = 0;
    ~NKey() { if (h) NCryptFreeObject(h); }
};
struct NProv {
    NCRYPT_PROV_HANDLE h = 0;
    ~NProv() { if (h) NCryptFreeObject(h); }
};
struct CertCtx {
    PCCERT_CONTEXT p = nullptr;
    ~CertCtx() { if (p) CertFreeCertificateContext(p); }
};
struct Store {
    HCERTSTORE h = nullptr;
    ~Store() { if (h) CertCloseStore(h, 0); }
};

std::string Fail(std::string* error, const std::string& what, DWORD code) {
    std::string msg = what + ": " + ErrorTextUtf8(code);
    if (error) *error = msg;
    return msg;
}

bool Encode(LPCSTR structType, const void* data, std::vector<BYTE>& out) {
    DWORD n = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, structType, data, 0, nullptr, nullptr, &n)) return false;
    out.resize(n);
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, structType, data, 0, nullptr, out.data(), &n)) return false;
    out.resize(n);
    return true;
}

bool NameBlob(const std::wstring& x500, std::vector<BYTE>& out) {
    DWORD n = 0;
    if (!CertStrToNameW(X509_ASN_ENCODING, x500.c_str(), CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, nullptr, nullptr, &n, nullptr))
        return false;
    out.resize(n);
    return CertStrToNameW(X509_ASN_ENCODING, x500.c_str(), CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, nullptr,
                          out.data(), &n, nullptr) != FALSE;
}

bool ExportPublicKey(NCRYPT_KEY_HANDLE key, std::vector<BYTE>& out) {
    DWORD n = 0;
    if (!CryptExportPublicKeyInfo(key, 0, X509_ASN_ENCODING, nullptr, &n)) return false;
    out.resize(n);
    return CryptExportPublicKeyInfo(key, 0, X509_ASN_ENCODING, reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(out.data()), &n) != FALSE;
}

// RFC 5280 method 1 key identifier: SHA-1 of the subjectPublicKey bits.
std::vector<BYTE> KeyId(const CERT_PUBLIC_KEY_INFO* spki) {
    std::vector<BYTE> id(20);
    DWORD n = (DWORD)id.size();
    CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, nullptr, spki->PublicKey.pbData, spki->PublicKey.cbData, id.data(), &n);
    return id;
}

SYSTEMTIME UnixToSystemTime(int64_t t) {
    ULARGE_INTEGER u;
    u.QuadPart = uint64_t(t * 10000000LL + 116444736000000000LL);
    FILETIME ft{u.LowPart, u.HighPart};
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    return st;
}

FILETIME UnixToFileTime(int64_t t) {
    ULARGE_INTEGER u;
    u.QuadPart = uint64_t(t * 10000000LL + 116444736000000000LL);
    return FILETIME{u.LowPart, u.HighPart};
}

std::string Thumbprint(PCCERT_CONTEXT c) {
    BYTE hash[20];
    DWORD n = sizeof hash;
    if (!CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, hash, &n)) return {};
    return Hex(hash, n);
}

std::vector<BYTE> FromHex(const std::string& hex) {
    std::vector<BYTE> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) out.push_back(BYTE(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}

struct Pair {
    CertCtx root;
    CertCtx leaf;
    int64_t notAfter = 0;
};

// Creates the single-use root (signed by caKey) and the leaf for leafKey. caKey is not persisted.
bool BuildPair(const std::string& host, NCRYPT_KEY_HANDLE caKey, NCRYPT_KEY_HANDLE leafKey, Pair& out, std::string* error) {
    std::wstring whost = FromUtf8(host);
    int64_t now = NowUnix();
    int64_t notBefore = now - 86400;
    out.notAfter = now + kLeafLifetimeDays * 86400;

    std::vector<BYTE> caSpkiBuf, leafSpkiBuf;
    if (!ExportPublicKey(caKey, caSpkiBuf) || !ExportPublicKey(leafKey, leafSpkiBuf)) {
        Fail(error, "Export public key", GetLastError());
        return false;
    }
    auto* caSpki = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(caSpkiBuf.data());
    auto* leafSpki = reinterpret_cast<PCERT_PUBLIC_KEY_INFO>(leafSpkiBuf.data());
    std::vector<BYTE> caKeyId = KeyId(caSpki);

    // ---- Root ----
    std::vector<BYTE> caName;
    if (!NameBlob(L"CN=wsrv " + whost + L" (single-use root), O=wsrv", caName)) {
        Fail(error, "Encode root name", GetLastError());
        return false;
    }
    CERT_NAME_BLOB caNameBlob{(DWORD)caName.size(), caName.data()};

    CERT_BASIC_CONSTRAINTS2_INFO caBc{TRUE, TRUE, 0};
    BYTE caKuByte = CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE;
    CRYPT_BIT_BLOB caKu{1, &caKuByte, 0};
    CRYPT_DATA_BLOB caSki{(DWORD)caKeyId.size(), caKeyId.data()};
    std::vector<BYTE> caBcEnc, caKuEnc, caSkiEnc;
    if (!Encode(X509_BASIC_CONSTRAINTS2, &caBc, caBcEnc) || !Encode(X509_KEY_USAGE, &caKu, caKuEnc) ||
        !Encode(X509_OCTET_STRING, &caSki, caSkiEnc)) {
        Fail(error, "Encode root extensions", GetLastError());
        return false;
    }
    CERT_EXTENSION caExt[] = {
        {const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2), TRUE, {(DWORD)caBcEnc.size(), caBcEnc.data()}},
        {const_cast<LPSTR>(szOID_KEY_USAGE), TRUE, {(DWORD)caKuEnc.size(), caKuEnc.data()}},
        {const_cast<LPSTR>(szOID_SUBJECT_KEY_IDENTIFIER), FALSE, {(DWORD)caSkiEnc.size(), caSkiEnc.data()}},
    };
    CERT_EXTENSIONS caExts{3, caExt};
    CRYPT_ALGORITHM_IDENTIFIER sigAlg{const_cast<LPSTR>(szOID_ECDSA_SHA256), {}};
    SYSTEMTIME stStart = UnixToSystemTime(notBefore), stEnd = UnixToSystemTime(out.notAfter);
    out.root.p = CertCreateSelfSignCertificate(caKey, &caNameBlob, CERT_CREATE_SELFSIGN_NO_KEY_INFO, nullptr, &sigAlg,
                                                 &stStart, &stEnd, &caExts);
    if (!out.root.p) {
        Fail(error, "Create root certificate", GetLastError());
        return false;
    }

    // ---- Leaf ----
    std::vector<BYTE> leafName;
    if (!NameBlob(L"CN=" + whost + L", O=wsrv", leafName)) {
        Fail(error, "Encode leaf name", GetLastError());
        return false;
    }
    CERT_ALT_NAME_ENTRY san{};
    san.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    san.pwszDNSName = whost.data();
    CERT_ALT_NAME_INFO sanInfo{1, &san};
    CERT_BASIC_CONSTRAINTS2_INFO leafBc{FALSE, FALSE, 0};
    BYTE leafKuByte = CERT_DIGITAL_SIGNATURE_KEY_USAGE;
    CRYPT_BIT_BLOB leafKu{1, &leafKuByte, 0};
    LPSTR ekuOid = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
    CERT_ENHKEY_USAGE eku{1, &ekuOid};
    CERT_AUTHORITY_KEY_ID2_INFO aki{};
    aki.KeyId = {(DWORD)caKeyId.size(), caKeyId.data()};
    std::vector<BYTE> leafKeyId = KeyId(leafSpki);
    CRYPT_DATA_BLOB leafSki{(DWORD)leafKeyId.size(), leafKeyId.data()};

    std::vector<BYTE> sanEnc, bcEnc, kuEnc, ekuEnc, akiEnc, skiEnc;
    if (!Encode(X509_ALTERNATE_NAME, &sanInfo, sanEnc) || !Encode(X509_BASIC_CONSTRAINTS2, &leafBc, bcEnc) ||
        !Encode(X509_KEY_USAGE, &leafKu, kuEnc) || !Encode(X509_ENHANCED_KEY_USAGE, &eku, ekuEnc) ||
        !Encode(X509_AUTHORITY_KEY_ID2, &aki, akiEnc) || !Encode(X509_OCTET_STRING, &leafSki, skiEnc)) {
        Fail(error, "Encode leaf extensions", GetLastError());
        return false;
    }
    CERT_EXTENSION leafExt[] = {
        {const_cast<LPSTR>(szOID_SUBJECT_ALT_NAME2), FALSE, {(DWORD)sanEnc.size(), sanEnc.data()}},
        {const_cast<LPSTR>(szOID_BASIC_CONSTRAINTS2), TRUE, {(DWORD)bcEnc.size(), bcEnc.data()}},
        {const_cast<LPSTR>(szOID_KEY_USAGE), TRUE, {(DWORD)kuEnc.size(), kuEnc.data()}},
        {const_cast<LPSTR>(szOID_ENHANCED_KEY_USAGE), FALSE, {(DWORD)ekuEnc.size(), ekuEnc.data()}},
        {const_cast<LPSTR>(szOID_AUTHORITY_KEY_IDENTIFIER2), FALSE, {(DWORD)akiEnc.size(), akiEnc.data()}},
        {const_cast<LPSTR>(szOID_SUBJECT_KEY_IDENTIFIER), FALSE, {(DWORD)skiEnc.size(), skiEnc.data()}},
    };

    // Positive 128-bit serial (CRYPT_INTEGER_BLOB is little-endian; top byte is the last).
    BYTE serial[16];
    BCryptGenRandom(nullptr, serial, sizeof serial, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    serial[15] = BYTE((serial[15] & 0x7F) | 0x01);

    CERT_INFO info{};
    info.dwVersion = CERT_V3;
    info.SerialNumber = {sizeof serial, serial};
    info.SignatureAlgorithm = sigAlg;
    info.Issuer = out.root.p->pCertInfo->Subject;
    info.NotBefore = UnixToFileTime(notBefore);
    info.NotAfter = UnixToFileTime(out.notAfter);
    info.Subject = {(DWORD)leafName.size(), leafName.data()};
    info.SubjectPublicKeyInfo = *leafSpki;
    info.cExtension = 6;
    info.rgExtension = leafExt;

    DWORD n = 0;
    if (!CryptSignAndEncodeCertificate(caKey, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &info, &sigAlg, nullptr, nullptr, &n)) {
        Fail(error, "Sign leaf certificate", GetLastError());
        return false;
    }
    std::vector<BYTE> der(n);
    if (!CryptSignAndEncodeCertificate(caKey, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &info, &sigAlg, nullptr, der.data(), &n)) {
        Fail(error, "Sign leaf certificate", GetLastError());
        return false;
    }
    out.leaf.p = CertCreateCertificateContext(X509_ASN_ENCODING, der.data(), n);
    if (!out.leaf.p) {
        Fail(error, "Load leaf certificate", GetLastError());
        return false;
    }
    return true;
}

bool CreateKey(NCRYPT_PROV_HANDLE prov, const wchar_t* name, DWORD flags, NKey& key, std::string* error) {
    SECURITY_STATUS s = NCryptCreatePersistedKey(prov, &key.h, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, flags);
    if (s == ERROR_SUCCESS) s = NCryptFinalizeKey(key.h, 0);
    if (s != ERROR_SUCCESS) { Fail(error, "Create key", (DWORD)s); return false; }
    return true;
}

void SetFriendlyName(PCCERT_CONTEXT c, const std::wstring& name) {
    CRYPT_DATA_BLOB b{DWORD((name.size() + 1) * sizeof(wchar_t)), (BYTE*)name.c_str()};
    CertSetCertificateContextProperty(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &b);
}

bool OpenMachineStore(const wchar_t* name, Store& s) {
    s.h = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, name);
    return s.h != nullptr;
}

void DeleteFromStore(const wchar_t* storeName, const std::string& thumbHex) {
    if (thumbHex.empty()) return;
    Store s;
    if (!OpenMachineStore(storeName, s)) return;
    auto hash = FromHex(thumbHex);
    CRYPT_HASH_BLOB blob{(DWORD)hash.size(), hash.data()};
    PCCERT_CONTEXT c = CertFindCertificateInStore(s.h, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
    if (c) CertDeleteCertificateFromStore(c);  // frees c
}

} // namespace

bool Issue(const std::string& host, Issued& out, std::string* error) {
    NProv prov;
    SECURITY_STATUS s = NCryptOpenStorageProvider(&prov.h, MS_KEY_STORAGE_PROVIDER, 0);
    if (s != ERROR_SUCCESS) { Fail(error, "Open key storage provider", (DWORD)s); return false; }

    NKey caKey, leafKey;
    if (!CreateKey(prov.h, nullptr, 0, caKey, error)) return false;  // ephemeral, never persisted
    std::wstring keyName = L"wsrv-" + FromUtf8(host) + L"-" + FromUtf8(RandomHex(4));
    if (!CreateKey(prov.h, keyName.c_str(), NCRYPT_MACHINE_KEY_FLAG, leafKey, error)) return false;

    Pair pair;
    bool built = BuildPair(host, caKey.h, leafKey.h, pair, error);
    NCryptFreeObject(caKey.h);  // the root's private key ceases to exist here
    caKey.h = 0;
    if (!built) { NCryptDeleteKey(leafKey.h, 0); leafKey.h = 0; return false; }

    std::wstring whost = FromUtf8(host);
    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = keyName.data();
    kpi.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
    kpi.dwProvType = 0;
    kpi.dwFlags = NCRYPT_MACHINE_KEY_FLAG;
    kpi.dwKeySpec = 0;

    Store my, root;
    if (!OpenMachineStore(L"MY", my) || !OpenMachineStore(L"Root", root)) {
        Fail(error, "Open certificate store", GetLastError());
        NCryptDeleteKey(leafKey.h, 0); leafKey.h = 0;
        return false;
    }
    PCCERT_CONTEXT addedLeaf = nullptr;
    if (!CertAddCertificateContextToStore(my.h, pair.leaf.p, CERT_STORE_ADD_REPLACE_EXISTING, &addedLeaf)) {
        Fail(error, "Add leaf to LocalMachine\\My", GetLastError());
        NCryptDeleteKey(leafKey.h, 0); leafKey.h = 0;
        return false;
    }
    CertSetCertificateContextProperty(addedLeaf, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi);
    SetFriendlyName(addedLeaf, L"wsrv " + whost);
    CertFreeCertificateContext(addedLeaf);

    PCCERT_CONTEXT addedRoot = nullptr;
    if (!CertAddCertificateContextToStore(root.h, pair.root.p, CERT_STORE_ADD_REPLACE_EXISTING, &addedRoot)) {
        Fail(error, "Add root to LocalMachine\\Root", GetLastError());
        DeleteFromStore(L"MY", Thumbprint(pair.leaf.p));
        NCryptDeleteKey(leafKey.h, 0); leafKey.h = 0;
        return false;
    }
    SetFriendlyName(addedRoot, L"wsrv " + whost + L" (single-use root)");
    CertFreeCertificateContext(addedRoot);

    out.leafThumb = Thumbprint(pair.leaf.p);
    out.rootThumb = Thumbprint(pair.root.p);
    out.keyName = ToUtf8(keyName);
    out.notAfter = pair.notAfter;
    log::Info("Issued certificate for " + host + " (" + out.leafThumb + ")");
    return true;
}

bool LeafPresent(const std::string& thumbHex) {
    Store s;
    if (!OpenMachineStore(L"MY", s)) return false;
    auto hash = FromHex(thumbHex);
    CRYPT_HASH_BLOB blob{(DWORD)hash.size(), hash.data()};
    PCCERT_CONTEXT c = CertFindCertificateInStore(s.h, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
    if (!c) return false;
    CertFreeCertificateContext(c);
    return true;
}

void Remove(const CertRecord& rec) {
    DeleteFromStore(L"MY", rec.leafThumb);
    DeleteFromStore(L"Root", rec.rootThumb);
    NProv prov;
    if (NCryptOpenStorageProvider(&prov.h, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
        NCRYPT_KEY_HANDLE k = 0;
        std::wstring name = FromUtf8(rec.keyName);
        if (NCryptOpenKey(prov.h, &k, name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG) == ERROR_SUCCESS) NCryptDeleteKey(k, 0);
    }
    log::Info("Removed certificate for " + rec.host);
}

bool SelfTest(const std::string& host, std::string* error) {
    NProv prov;
    SECURITY_STATUS s = NCryptOpenStorageProvider(&prov.h, MS_KEY_STORAGE_PROVIDER, 0);
    if (s != ERROR_SUCCESS) { Fail(error, "Open key storage provider", (DWORD)s); return false; }
    NKey caKey, leafKey;
    if (!CreateKey(prov.h, nullptr, 0, caKey, error) || !CreateKey(prov.h, nullptr, 0, leafKey, error)) return false;
    Pair pair;
    if (!BuildPair(host, caKey.h, leafKey.h, pair, error)) return false;

    if (!CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void*)pair.leaf.p,
                                           CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)pair.root.p, 0, nullptr)) {
        Fail(error, "Leaf signature does not verify against root", GetLastError());
        return false;
    }
    if (!CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void*)pair.root.p,
                                           CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)pair.root.p, 0, nullptr)) {
        Fail(error, "Root is not self-signed", GetLastError());
        return false;
    }
    // SAN must contain exactly the host.
    PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2, pair.leaf.p->pCertInfo->cExtension,
                                            pair.leaf.p->pCertInfo->rgExtension);
    if (!ext) { if (error) *error = "Leaf has no SAN"; return false; }
    DWORD n = 0;
    CERT_ALT_NAME_INFO* alt = nullptr;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &alt, &n)) {
        Fail(error, "Decode SAN", GetLastError());
        return false;
    }
    bool sanOk = alt->cAltEntry == 1 && alt->rgAltEntry[0].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME &&
                 FromUtf8(host) == alt->rgAltEntry[0].pwszDNSName;
    LocalFree(alt);
    if (!sanOk) { if (error) *error = "SAN does not match host"; return false; }

    // Chain-build against an in-memory trust anchor, policy-checked for SSL server use.
    HCERTSTORE mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    CertAddCertificateContextToStore(mem, pair.root.p, CERT_STORE_ADD_ALWAYS, nullptr);
    CERT_CHAIN_ENGINE_CONFIG cfg{};
    cfg.cbSize = sizeof cfg;
    cfg.hExclusiveRoot = mem;
    HCERTCHAINENGINE engine = nullptr;
    bool chainOk = false;
    if (CertCreateCertificateChainEngine(&cfg, &engine)) {
        CERT_CHAIN_PARA para{};
        para.cbSize = sizeof para;
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        if (CertGetCertificateChain(engine, pair.leaf.p, nullptr, nullptr, &para, 0, nullptr, &chain)) {
            std::wstring whost = FromUtf8(host);
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
            ssl.cbSize = sizeof ssl;
            ssl.dwAuthType = AUTHTYPE_SERVER;
            ssl.pwszServerName = whost.data();
            CERT_CHAIN_POLICY_PARA pp{};
            pp.cbSize = sizeof pp;
            pp.pvExtraPolicyPara = &ssl;
            CERT_CHAIN_POLICY_STATUS ps{};
            ps.cbSize = sizeof ps;
            if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps)) {
                chainOk = ps.dwError == 0;
                if (!chainOk) Fail(error, "SSL chain policy", ps.dwError);
            }
            CertFreeCertificateChain(chain);
        }
        CertFreeCertificateChainEngine(engine);
    }
    CertCloseStore(mem, 0);
    return chainOk;
}

// ---------------------------------------------------------------------------------------------
// SNI bindings

namespace {

void FillKey(HTTP_SERVICE_CONFIG_SSL_SNI_KEY& key, std::wstring& host, int port) {
    key = {};
    auto* sa = reinterpret_cast<SOCKADDR_IN*>(&key.IpPort);
    sa->sin_family = AF_INET;
    sa->sin_port = _byteswap_ushort(USHORT(port));
    key.Host = host.data();
}

} // namespace

DWORD BindSni(const std::wstring& hostIn, int port, const std::string& thumbHex) {
    std::wstring host = hostIn;
    auto hash = FromHex(thumbHex);

    // Already bound to the same certificate? Nothing to do.
    HTTP_SERVICE_CONFIG_SSL_SNI_QUERY q{};
    q.QueryDesc = HttpServiceConfigQueryExact;
    FillKey(q.KeyDesc, host, port);
    std::vector<BYTE> buf(4096);
    ULONG ret = 0;
    ULONG r = HttpQueryServiceConfiguration(nullptr, HttpServiceConfigSslSniCertInfo, &q, sizeof q, buf.data(),
                                            (ULONG)buf.size(), &ret, nullptr);
    if (r == NO_ERROR) {
        auto* existing = reinterpret_cast<HTTP_SERVICE_CONFIG_SSL_SNI_SET*>(buf.data());
        if (existing->ParamDesc.SslHashLength == hash.size() &&
            memcmp(existing->ParamDesc.pSslHash, hash.data(), hash.size()) == 0)
            return NO_ERROR;
        UnbindSni(hostIn, port);
    }

    HTTP_SERVICE_CONFIG_SSL_SNI_SET set{};
    FillKey(set.KeyDesc, host, port);
    set.ParamDesc.SslHashLength = (ULONG)hash.size();
    set.ParamDesc.pSslHash = hash.data();
    set.ParamDesc.AppId = kAppId;
    set.ParamDesc.pSslCertStoreName = const_cast<PWSTR>(L"MY");
    set.ParamDesc.DefaultFlags = HTTP_SERVICE_CONFIG_SSL_FLAG_DISABLE_LEGACY_TLS;
    return HttpSetServiceConfiguration(nullptr, HttpServiceConfigSslSniCertInfo, &set, sizeof set, nullptr);
}

DWORD UnbindSni(const std::wstring& hostIn, int port) {
    std::wstring host = hostIn;
    HTTP_SERVICE_CONFIG_SSL_SNI_SET set{};
    FillKey(set.KeyDesc, host, port);
    ULONG r = HttpDeleteServiceConfiguration(nullptr, HttpServiceConfigSslSniCertInfo, &set, sizeof set, nullptr);
    return r == ERROR_FILE_NOT_FOUND ? NO_ERROR : r;
}

} // namespace wsrv::certs
