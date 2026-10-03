"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const c of children) if (c != null) node.append(c);
  return node;
};

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch("/api" + path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || `Request failed (${res.status}).`);
  return data;
}

let sites = [];
let editing = null; // site being edited, or null when adding

function displayUrl(s) {
  return "https://" + s.host + (s.port === 443 ? "" : ":" + s.port);
}

function renderState(status) {
  const state = $("state");
  state.replaceChildren();
  const h3Text = {
    enabled: ["ok", "HTTP/3 on",
      "HTTP/3 is enabled in Windows. Browsers discover it through the Alt-Svc header on the first HTTP/2 response."],
    pending: ["warn", "HTTP/3 after reboot",
      "HTTP/3 is turned on in Windows but takes effect after the next reboot. Sites are served over HTTP/2 until then."],
    disabled: ["warn", "HTTP/3 off",
      "HTTP/3 is disabled in Windows (http.sys EnableHttp3). Run “wsrv install” as administrator, then reboot. Sites are served over HTTP/2 until then."],
  }[status.http3] || ["warn", "HTTP/3 unknown", ""];
  state.append(`Running ${status.version}. `, el("span", { className: h3Text[0], textContent: h3Text[1] }));
  $("h3-state").textContent = h3Text[2];
  $("edge-cmd").textContent = status.edgeCommand;
  $("access-log").checked = status.accessLog;
  $("log-path").textContent = status.dataDir + "\\logs\\access.log";
  $("fallback").hidden = !status.helloFallback;
}

function renderSites() {
  const list = $("sites");
  list.replaceChildren();
  $("empty").hidden = sites.length > 0;
  list.hidden = sites.length === 0;
  for (const s of sites) {
    const bad = s.enabled && s.errors.length > 0;
    const li = el("li", { className: "route" + (s.enabled ? "" : " off") + (bad ? " bad" : "") });
    li.append(el("span", { className: "dot", title: !s.enabled ? "Off" : bad ? "Problem" : "Serving" }));
    li.append(el("a", { className: "addr-link", href: s.url, target: "_blank", rel: "noopener", textContent: displayUrl(s) }));
    const root = el("div", { className: "root" },
      el("span", { className: "arrow", textContent: "→", ariaHidden: "true" }),
      el("span", { className: "path", textContent: s.root || "“Hello, world!” page" }));
    if (s.name && s.name !== s.host) root.append(el("span", { className: "name", textContent: s.name }));
    li.append(root);

    const toggle = el("input", { type: "checkbox", checked: s.enabled, ariaLabel: `Serve ${displayUrl(s)}` });
    toggle.addEventListener("change", async () => {
      toggle.disabled = true;
      try { await api("PUT", `/sites/${s.id}`, { enabled: toggle.checked }); }
      catch (e) { toggle.checked = !toggle.checked; alertState(e.message); }
      await refresh();
    });
    const edit = el("button", { className: "quiet", textContent: "Edit" });
    edit.addEventListener("click", () => openEditor(s));
    li.append(el("div", { className: "acts" }, el("label", { className: "switch" }, toggle), edit));

    if (s.enabled && s.errors.length) {
      li.append(el("ul", { className: "errs" }, ...s.errors.map((e) => el("li", { textContent: e }))));
    }
    list.append(li);
  }
}

function alertState(message) {
  const state = $("state");
  state.replaceChildren(el("span", { className: "warn", textContent: message }));
}

async function refresh() {
  try {
    const [status, list] = await Promise.all([api("GET", "/status"), api("GET", "/sites")]);
    sites = list;
    $("signed-out").hidden = true;
    $("app").hidden = false;
    $("signout").hidden = false;
    renderState(status);
    renderSites();
  } catch (e) {
    if (e.status === 401) {
      $("app").hidden = true;
      $("signout").hidden = true;
      $("signed-out").hidden = false;
      $("state").textContent = "Signed out";
    } else {
      alertState(e.message);
    }
  }
}

// ---- Editor dialog ----

function openEditor(site) {
  editing = site || null;
  $("editor-title").textContent = site ? "Edit web root" : "Add web root";
  $("save").textContent = site ? "Save changes" : "Add web root";
  $("f-host").value = site ? site.host.replace(/^local\./, "") : "";
  $("f-port").value = site ? site.port : 443;
  $("f-root").value = site && site.root ? site.root : "";
  $("f-name").value = site && site.name !== site.host ? site.name : "";
  $("f-enabled").checked = site ? site.enabled : true;
  $("f-listing").checked = site ? site.dirListing : false;
  $("f-hidden").checked = site ? site.serveHidden : false;
  $("f-cache").value = site ? site.cacheControl : "no-cache";
  $("form-error").hidden = true;
  $("browser").hidden = true;
  const del = $("delete");
  del.hidden = !site;
  del.textContent = "Delete";
  del.dataset.armed = "";
  $("editor").showModal();
  $("f-host").focus();
}

function showFormError(msg) {
  const e = $("form-error");
  e.textContent = msg;
  e.hidden = false;
}

$("site-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const host = $("f-host").value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^local\./, "");
  if (!host) return showFormError("Enter the part of the address after “local.”, for example blog.");
  const port = Number($("f-port").value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return showFormError("Port must be a whole number from 1 to 65535.");
  const body = {
    host: "local." + host,
    port,
    root: $("f-root").value.trim() || null,
    name: $("f-name").value.trim(),
    enabled: $("f-enabled").checked,
    dirListing: $("f-listing").checked,
    serveHidden: $("f-hidden").checked,
    cacheControl: $("f-cache").value.trim(),
  };
  const save = $("save");
  save.disabled = true;
  try {
    if (editing) await api("PUT", `/sites/${editing.id}`, body);
    else await api("POST", "/sites", body);
    $("editor").close();
    await refresh();
  } catch (e) {
    showFormError(e.message);
  } finally {
    save.disabled = false;
  }
});

$("cancel").addEventListener("click", () => $("editor").close());

$("delete").addEventListener("click", async () => {
  const del = $("delete");
  if (!del.dataset.armed) {
    del.dataset.armed = "1";
    del.textContent = `Delete ${editing.host}?`;
    return;
  }
  del.disabled = true;
  try {
    await api("DELETE", `/sites/${editing.id}`);
    $("editor").close();
    await refresh();
  } catch (e) {
    showFormError(e.message);
  } finally {
    del.disabled = false;
  }
});

// ---- Folder browser ----

let browsePath = "";
let browseParent = null;

async function browse(path) {
  const list = $("browser-list");
  try {
    const data = await api("GET", "/fs?path=" + encodeURIComponent(path));
    browsePath = data.path;
    browseParent = data.parent;
    $("browser-path").textContent = data.path || "This PC";
    $("up").disabled = data.parent === null;
    $("choose").disabled = !data.path;
    list.replaceChildren();
    if (!data.dirs.length) list.append(el("li", { className: "none", textContent: "No subfolders" }));
    for (const d of data.dirs) {
      const b = el("button", { type: "button", textContent: d.name });
      b.addEventListener("click", () => browse(d.path));
      list.append(el("li", {}, b));
    }
  } catch (e) {
    list.replaceChildren(el("li", { className: "none", textContent: e.message }));
  }
}

$("browse").addEventListener("click", () => {
  const box = $("browser");
  box.hidden = !box.hidden;
  if (!box.hidden) browse($("f-root").value.trim());
});
$("up").addEventListener("click", () => { if (browseParent !== null) browse(browseParent); });
$("choose").addEventListener("click", () => {
  if (!browsePath) return;
  $("f-root").value = browsePath;
  $("browser").hidden = true;
  $("f-root").focus();
});

// ---- Page actions ----

$("add").addEventListener("click", () => openEditor(null));
$("add-empty").addEventListener("click", () => openEditor(null));
$("copy-cmd").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("edge-cmd").textContent);
    $("copy-cmd").textContent = "Copied";
    setTimeout(() => ($("copy-cmd").textContent = "Copy"), 1500);
  } catch { /* clipboard blocked; the command is selectable */ }
});
$("access-log").addEventListener("change", async (ev) => {
  try { renderState(await api("PUT", "/settings", { accessLog: ev.target.checked })); }
  catch (e) { ev.target.checked = !ev.target.checked; alertState(e.message); }
});
$("signout").addEventListener("click", async () => {
  try { await api("POST", "/logout"); } catch { /* already signed out */ }
  await refresh();
});

refresh();
