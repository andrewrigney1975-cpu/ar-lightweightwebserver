# wsrv

A super-lightweight HTTPS / HTTP/3 static web server for Windows 11 x64.

- Map any number of local folders to addresses like `https://local.blog` or `https://local.docs:8443`.
- HTTPS only, with locally trusted certificates created automatically.
- HTTP/3 (QUIC), HTTP/2 and HTTP/1.1 through Windows' built-in `http.sys`.
- `GET` and `HEAD` only. No CGI, no server-side code: content sites are read-only.
- Visitors can't reach anything outside a site's folder.
- Manage everything at **https://local.admin:8192**.
- One 1.5 MB `wsrv.exe`. Runtime dependencies are Windows system DLLs only
  (`httpapi`, `crypt32`, `ncrypt`, `advapi32`, `shell32`, `ole32`, `user32`, `kernel32`).

See [PLAN.md](PLAN.md) for the design and the reasoning behind it.

## Install

From an **elevated** prompt:

```
wsrv install
```

This copies `wsrv.exe` to `C:\Program Files\wsrv`, creates the private configuration database in
`C:\ProgramData\wsrv` (SYSTEM and Administrators only), enables HTTP/3 in http.sys, installs and
starts the `wsrv` Windows service (automatic start, restarts on failure) and adds a **wsrv Admin**
Start-menu shortcut.

If HTTP/3 was not already enabled in http.sys, reboot once; until then sites are served over HTTP/2.

## Use

Open **wsrv Admin** from the Start menu (or run `wsrv open-admin`). It signs you in to
https://local.admin:8192 with a single-use link. Only the user who ran `wsrv install` and
Administrators can obtain sign-in links.

In the admin site, **Add web root**: choose an address (`local.` + a name), a port and a folder.
wsrv then, without a restart:

1. creates a certificate for the address and trusts it on this machine,
2. binds it in http.sys for that address and port,
3. adds the address to the hosts file (pointing at `127.0.0.1` and `::1`),
4. starts serving the folder.

Leave the folder empty to serve a black "Hello, world!" page. When no folders are mapped at all,
`https://localhost/` shows that page too.

### Commands

| Command | |
|---|---|
| `wsrv install` | Install and start the service (elevated). |
| `wsrv uninstall [--purge]` | Remove the service, certificates, TLS bindings, hosts entries and shortcut. `--purge` also deletes the database and logs. |
| `wsrv open-admin` | Sign in to the admin site in your browser. |
| `wsrv run [--data DIR] [--open]` | Run in the foreground for development (elevated; stop the service first). |
| `wsrv status` | Service and HTTP/3 status. |

## Seeing HTTP/3 in a browser

Browsers learn about HTTP/3 from the `Alt-Svc` header on an HTTP/2 response. Chromium-based
browsers (Edge, Chrome) refuse QUIC with certificates that don't chain to a public root unless
the origin is forced, so local sites normally stay on HTTP/2. The admin site shows a ready-made
command that opens a separate Edge profile with
`--origin-to-force-quic-on=<your sites>`. Check the **Protocol** column (`h3`) in DevTools → Network.

## Static file behaviour

- `index.html` / `index.htm` for folders; folders without a trailing `/` redirect.
- `ETag`, `Last-Modified`, `304 Not Modified`, single byte ranges (`206`/`416`), `If-Range`.
- Pre-compressed siblings: `app.js.br` / `app.js.gz` are served for `app.js` when the browser accepts them.
- Optional directory listing and per-site `Cache-Control` (default `no-cache`).
- Hidden/system files and dot-files are not served unless enabled per site.
- Any other method gets `405 Method Not Allowed` with `Allow: GET, HEAD`.
- Requests from other machines are refused: wsrv is for local access only.

## Security model

- **Containment.** Each request path is checked segment by segment (no `..`, `\`, `:`, device
  names, trailing dots or spaces, control characters). The file is then opened and its *final*
  on-disk path, after junctions, symlinks and 8.3 names are resolved, must still be inside the
  site's folder. The configuration directory can never be served, even if a site folder contains it.
- **Certificates.** For each address wsrv creates a single-use root CA, signs one leaf certificate
  and **destroys the CA's private key immediately**. The trusted root therefore can't be used to
  sign anything else. Leaf keys are non-exportable machine keys.
- **Admin site.** Loopback only; the `Host` must be exactly `local.admin:8192` (blocks DNS
  rebinding); session cookie is `Secure; HttpOnly; SameSite=Strict`; changes require a matching
  `Origin` and a JSON body; strict Content-Security-Policy. Sign-in tokens come from a named pipe
  limited to SYSTEM, Administrators and the installing user, and the client checks that the pipe
  belongs to wsrv.
- **Configuration** lives in SQLite at `C:\ProgramData\wsrv\wsrv.db`, readable only by SYSTEM and
  Administrators, and is never reachable over HTTP.
- The service runs as LocalSystem, which it needs to manage certificates, http.sys bindings and the
  hosts file.

## Build

Requires Visual Studio 2022+ (or Build Tools) with the C++ x64 workload and CMake.

```
build.cmd            :: Release build -> build\Release\wsrv.exe
build\Release\wsrv_tests.exe
```

The test suite needs no elevation. It covers the path guard (including a traversal corpus,
junction and symlink escapes), ranges, conditional requests, JSON, the hosts-file editor, the
SQLite store, certificate generation and chain validation, and the admin API. It also runs
over-the-wire tests against real http.sys using Windows' built-in `Temporary_Listen_Addresses`
reservation.

After `wsrv install`, `tests\smoke.ps1` (elevated) checks the installed service end to end.

SQLite 3.53.4 is vendored in `third_party/sqlite` (public domain).

## License

MIT. See [LICENSE](LICENSE).
