# wsrv — Implementation Plan

Super-lightweight HTTPS / HTTP/3 static web server for Windows 11 x64.

## Requirements

- Owner maps any number of local folders as web roots, each on its own **port and/or `local.*` alias**
  (aliases always start with `local.` so they never collide with real domains).
- **HTTPS only.** No plain-HTTP listeners.
- Visitors **cannot traverse outside / above** a web root.
- Content sites implement **GET and HEAD only**. No server-side languages, no CGI.
- A web root with no folder mapped (or no sites at all) shows **"Hello, world!"** — white text,
  centred, on black.
- Owner manages sites visually at **https://local.admin:8192**.
- Configuration lives in **SQLite**, which is never exposed by the server.
- Name: **wsrv**.

### Resolved assumptions

1. The admin site (`local.admin:8192`) may use **all verbs** (REST API). The GET/HEAD restriction
   applies to content sites.
2. **Local access only** — requests from non-loopback addresses are rejected.
3. Falling back to **HTTP/2** when a browser refuses HTTP/3 with a locally-trusted certificate is
   acceptable.

## Core decision — let Windows do the HTTP/3 work

Windows 11's kernel HTTP stack **http.sys** (`httpapi.dll`) speaks HTTP/1.1, HTTP/2 and
HTTP/3 (QUIC) with TLS 1.3 via Schannel. Building on it means **zero third-party
network/TLS/QUIC code**.

| Option | Runtime deps | Verdict |
|---|---|---|
| **C++20 + http.sys (Win32)** | In-box DLLs only | **Chosen** |
| MsQuic + nghttp3 | msquic.dll + own H3 layer | Fallback only |
| .NET Kestrel | .NET runtime / 30–70 MB | Too heavy |
| Rust quinn/h3/rustls, Go quic-go | many crates / third-party QUIC | Not "few deps" |

Deliverable: one `wsrv.exe` (static CRT), SQLite amalgamation compiled in (public domain,
vendored in `third_party/sqlite`), admin UI embedded as resources. Runtime dependencies:
Windows system DLLs only.

## Known risks

1. HTTP/3 in http.sys is off by default — `install` sets `EnableHttp3=1` / `EnableAltSvc=1`
   under `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters` (reboot or HTTP-service
   restart required).
2. Chromium browsers refuse QUIC to certificates chaining to non-public roots unless the
   origin is forced (`--origin-to-force-quic-on=host:port`). Firefox has a similar pref.
   Browsers will otherwise fall back to HTTP/2 (accepted). The admin UI offers a ready-made
   Edge command line.
3. In-box `curl.exe` lacks HTTP/3; verify with browser devtools (Protocol = `h3`).

## Architecture

```
Browser ──TCP/UDP─▶ http.sys ──▶ request queue ──▶ thread-pool IOCP ──▶ router (URL context)
 (h2 / h3)          TLS, QUIC,                                          ├─ static site handler (GET/HEAD)
                    SNI certs                                           ├─ hello handler
                                                                        └─ admin handler + REST API
                 config store (SQLite, %ProgramData%\wsrv\wsrv.db)  ◀───┘
                 reconciler: certs (CNG) · SNI bindings · hosts file · URL registrations
```

- One server session / URL group / request queue. Each site registers
  `https://local.foo:PORT/` with its site id as URL context ⇒ no routing table lookup.
- Async receives/sends on a Windows thread-pool I/O object; file bodies are sent by the
  kernel straight from the file handle.
- Admin changes are applied live by the reconciler (no restart).

## Feature design

### Sites & names
- Unique `(host, port)`. Host must match `^local\.[a-z0-9-]+(\.[a-z0-9-]+)*$`;
  `local.admin` is reserved.
- wsrv maintains a delimited block in the hosts file mapping each alias to `127.0.0.1`
  and `::1`.

### HTTPS / certificates
- Per host: a fresh **ephemeral root CA** (ECDSA P-256) signs one leaf certificate
  (SAN = that host, EKU serverAuth); the CA private key is **destroyed immediately**, so
  there is no reusable CA key on disk to steal. Root → `LocalMachine\Root`,
  leaf + persisted machine key → `LocalMachine\My`.
- Leaf bound to `host:port` via http.sys SNI binding. Auto-renewed at startup when < 30 days
  remain. Removed when the host is no longer used.
- Responses carry HSTS and `X-Content-Type-Options: nosniff`, plus `Alt-Svc: h3`.

### Traversal defence (`path_guard`)
1. Use http.sys's decoded, dot-segment-normalised path.
2. Reject NUL/control chars, `\ : * ? " < > |`, `.`/`..` segments, trailing dot/space,
   reserved device names (`CON`, `NUL`, `COM1`, …).
3. Open with `\\?\` + root + relative path, then `GetFinalPathNameByHandleW`; final path must
   equal the root's final path or start with it + `\`. Defeats junctions, symlinks, 8.3 names,
   case tricks.
4. Hidden/system files and dot-files refused by default (per-site toggle), checked on the
   final path.
5. A root may not contain (or sit inside) `%ProgramData%\wsrv`; serve-time double check too.

### GET/HEAD static serving
- Other verbs ⇒ `405` + `Allow: GET, HEAD`.
- `index.html`/`index.htm`, MIME table (DB-overridable), `ETag`/`Last-Modified` with
  `If-None-Match`/`If-Modified-Since` ⇒ `304`, single byte `Range` + `If-Range`, pre-compressed
  `.br`/`.gz` siblings, optional directory listing (off by default), per-site `Cache-Control`.

### Hello, world
- A site with no folder serves the built-in page; with no folder-mapped site at all,
  `https://localhost:443/` serves it too.

### Admin UI — https://local.admin:8192
- Vanilla HTML/CSS/JS embedded in the exe. List/add/edit/enable/delete sites, server-side
  folder browser, per-site cert/binding status, HTTP/3 status, Edge HTTP/3 launch command.
- Security: loopback only; `Host` must equal `local.admin:8192`; session cookie
  (`Secure; HttpOnly; SameSite=Strict`); mutating requests need matching `Origin` and JSON.
- Login: Start-menu shortcut runs `wsrv open-admin`, which obtains a one-time token from the
  service over a named pipe (ACL: SYSTEM, Administrators, installing owner; the client also
  verifies the pipe server is wsrv.exe) and opens `https://local.admin:8192/login?t=…`.

### SQLite config
- `%ProgramData%\wsrv\wsrv.db`, directory ACL: SYSTEM + Administrators only.
- Tables: `sites`, `certs`, `bindings`, `mime_types`, `settings`; versioned with
  `PRAGMA user_version`.

## Delivery model — **Windows Service** (recommended)

| Factor | Service | On-demand app |
|---|---|---|
| Needs admin for hosts / SNI bindings / machine certs | always has it | UAC every launch |
| Sites up at boot, before login | yes | no |
| Crash recovery | SCM recovery actions | none |
| UI | not needed (browser admin) | tray icon = more code |

One exe, subcommands: `install`, `uninstall [--purge]`, `run` (foreground console, for
development), `service` (SCM entry), `open-admin`, `version`.
v1 runs as **LocalSystem** (required for hosts / cert store / http.sys config); containment
relies on `path_guard`. v2 option: serve under a restricted identity for OS-enforced
containment.

Logging: Windows Event Log (lifecycle/errors) + `%ProgramData%\wsrv\logs\wsrv.log`; optional
access log.

## Layout

```
CMakeLists.txt, build.cmd
src/        main, service, server, httpsys, router/static/hello/admin handlers, path_guard,
            http_util, mime, json, config_store, certs, hosts_file, reconciler, pipe, log, util
admin-ui/   index.html, app.css, app.js  (embedded via wsrv.rc)
third_party/sqlite/   sqlite3.c, sqlite3.h
tests/      unit tests (wsrv_tests.exe), integration.ps1 (elevated)
```

## Phases

| # | Phase | Output |
|---|---|---|
| 0 | Spike | http.sys + self-signed SNI cert serving over h3; browser behaviour confirmed |
| 1 | Core server | `wsrv run`, GET/HEAD, path guard, hello, 405, MIME, ETag/304 |
| 2 | Config & multi-site | SQLite store, migrations, multi-site, hot reload |
| 3 | Certs & names | per-alias certs, SNI bindings, renewal, hosts manager |
| 4 | Service | SCM, install/uninstall, recovery, Event Log, HTTP/3 registry |
| 5 | Admin UI | REST API, pipe login, folder browser, embedded UI |
| 6 | Hardening | traversal corpus, ranges/conditionals, load test, docs |

## Acceptance criteria

- Adding `local.myblog → D:\sites\blog` in the admin UI makes `https://local.myblog` work
  without restart or certificate warning.
- With HTTP/3 permitted by the browser, devtools shows `h3`.
- Every traversal-corpus request returns 400/404; nothing outside the root is opened.
- `POST`/`PUT`/`DELETE` ⇒ 405 on content sites; `HEAD` headers equal `GET` headers.
- Empty configuration shows the black "Hello, world!" page.
- `wsrv uninstall` leaves no certs, hosts entries, http.sys bindings or service behind.
- `dumpbin /imports wsrv.exe` lists only Windows system DLLs.
