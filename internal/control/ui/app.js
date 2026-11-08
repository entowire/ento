// The dashboard of an ento network. The control node knows the calling device by its overlay
// address, and answers its API in a session of that device only: the page shows a code, which the
// device approves with its key (`ento admin ui CODE`); every change carries the X-Ento-UI header,
// which pages of other origins cannot send. Plain DOM, no framework, nothing loaded from elsewhere.
"use strict";

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";

// el builds an element: attributes (on* take a function), then children (strings, nodes, arrays).
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k);
  return e;
}

// put replaces an element's children, leaving out empty slots (null, false), which the DOM would
// otherwise write out as text.
function put(node, ...kids) {
  node.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
}

function icon(name, size = 18) {
  const s = document.createElementNS(SVG, "svg");
  s.setAttribute("width", size);
  s.setAttribute("height", size);
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVG, "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
}

const button = (label, onclick, cls = "btn xs", attrs = {}) =>
  el("button", { type: "button", class: cls, ...attrs, onclick: (e) => { e.stopPropagation(); onclick(e); } }, label);
const tag = (text, cls = "tag", attrs = {}) => el("span", { class: cls, ...attrs }, text);
const badge = (text, kind = "mute", attrs = {}) => el("span", { class: "badge " + kind, ...attrs }, text);
const empty = (text) => el("div", { class: "empty" }, text);
const list = (items, none) => items.length ? items : [empty(none)];

// auto: the page's own periodic refresh, which does not keep the session alive.
async function call(method, path, body, auto = false) {
  const opts = { method, headers: {}, cache: "no-store" };
  if (method !== "GET") opts.headers["X-Ento-UI"] = "1";
  if (auto) opts.headers["X-Ento-Refresh"] = "1";
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 204) return null;
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (!r.ok) {
    const err = new Error((data && data.error) || `HTTP ${r.status}`);
    err.status = r.status;
    throw err;
  }
  return data;
}

// copyText puts text on the clipboard and says so.
async function copyText(text, what = "Command") {
  try { await navigator.clipboard.writeText(text); notice(`${what} copied.`, true); }
  catch { notice("Copy it by hand: the browser did not allow copying."); }
}

// command shows a command to run, with a copy button; the prompt is drawn by CSS, so neither
// selecting nor copying takes it.
function command(text) {
  const pre = el("pre", { class: "term cmd" }, text);
  return el("div", { class: "term-wrap" }, pre, el("button", { type: "button", class: "copy", title: "Copy the command", "aria-label": "Copy the command",
    onclick: () => copyText(pre.textContent) }, icon("copy", 16)));
}
document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copyText($(b.dataset.copy).textContent)));

// --- messages -------------------------------------------------------------------------------------
let toastTimer = null;
// notice shows a message in the browser's top layer, so it stays above an open dialog (not under
// its blurred backdrop).
function notice(text, ok = false) {
  clearTimeout(toastTimer);
  const t = $("toast");
  $("toast-text").textContent = text;
  t.className = "toast" + (ok ? "" : " bad");
  if (t.matches(":popover-open")) t.hidePopover();
  if (!text) return;
  t.showPopover(); // shown again after a dialog opened: on top of it
  if (ok) toastTimer = setTimeout(() => { if (t.matches(":popover-open")) t.hidePopover(); }, 5000);
}
$("toast-close").addEventListener("click", () => { if ($("toast").matches(":popover-open")) $("toast").hidePopover(); });

// The version of the control node that served this page; a page left open across an update runs its
// old script until reloaded.
const pageVersion = document.querySelector('meta[name="ento-version"]')?.content || "";
function checkPageVersion() {
  const b = $("banner");
  if (pageVersion && info && info.version && info.version !== pageVersion) {
    b.textContent = `The control plane now runs ento ${info.version}; this page is from ${pageVersion}: reload it.`;
    b.hidden = false;
  } else b.hidden = true;
}

// --- time -----------------------------------------------------------------------------------------
function ago(iso) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 0) return "in " + span(-s);
  if (s < 5) return "just now";
  return span(s) + " ago";
}
function until(iso) {
  const s = Math.round((Date.parse(iso) - Date.now()) / 1000);
  return s <= 0 ? "expired" : "in " + span(s);
}
function span(s) {
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  const d = Math.round(s / 86400);
  return d === 1 ? "1 day" : `${d} days`;
}
const when = (iso) => iso ? new Date(iso).toLocaleString() : "";
const online = (p) => p.last_seen && Date.now() - Date.parse(p.last_seen) < 180000;
const latest = (...isos) => isos.filter(Boolean).sort((a, b) => Date.parse(b) - Date.parse(a))[0] || "";
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const few = (names, n = 4) => names.slice(0, n).join(", ") + (names.length > n ? ` and ${names.length - n} more` : "");

// Devices named after their host name carry this prefix; an administrator's names never do.
const selfPrefix = "z-";
// The name a device gets when its reported host name is confirmed (as names.FromReported does).
function fromReported(s) {
  let l = (s || "").trim().split(".")[0].toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  while (l.startsWith(selfPrefix)) l = l.slice(selfPrefix.length);
  if (!l) l = "device";
  return l.length > 32 ? l.slice(0, 32).replace(/-+$/, "") : l;
}

// initials of a person (their name, or the part of their e-mail address before @).
function initials(name) {
  const words = (name || "?").split("@")[0].split(/[\s._-]+/).filter(Boolean);
  return (words.length > 1 ? words[0][0] + words[1][0] : (words[0] || "?").slice(0, 2)).toUpperCase();
}

// --- dialog ---------------------------------------------------------------------------------------
function ask(title, text, { input = null, body = null, ok = "OK", danger = false } = {}) {
  return new Promise((resolve) => {
    const d = $("dialog");
    $("dialog-title").textContent = title;
    $("dialog-text").textContent = text;
    $("dialog-text").hidden = !text;
    put($("dialog-body"), ...(body ? [body] : []));
    const inp = $("dialog-input");
    inp.hidden = input === null;
    inp.value = input ?? "";
    // Enter confirms (the form's first button, which it would press, is Cancel).
    inp.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); d.close("ok"); } };
    const okb = $("dialog-ok");
    okb.textContent = ok;
    okb.className = danger ? "btn danger solid" : "btn primary";
    d.returnValue = "cancel";
    d.onclose = () => resolve(d.returnValue === "ok" ? (input === null ? true : inp.value) : null);
    d.showModal();
    if (input !== null) inp.focus();
  });
}

// --- state ----------------------------------------------------------------------------------------
let info = null, peers = [], tokens = [], policies = [], links = [], auths = [], checks = [], routes = [];
let dns = { domain: "", records: [], forwards: [] };
const tabs = ["overview", "people", "devices", "groups", "access", "routes", "names", "links", "activity"];
const ui = { person: null, device: null, group: null, peopleFilter: "all", deviceFilter: "all" };

function tab() {
  const t = (location.hash || "#overview").slice(1);
  return tabs.includes(t) ? t : "overview";
}

async function load(which, auto = false) {
  const get = (path) => call("GET", path, undefined, auto);
  try {
    if (!info || auto) info = await get("/v1/admin/info");
    renderMe();
    checkPageVersion();
    const t = which || tab();
    if (t === "overview") {
      let recent;
      [info, peers, tokens, idp, recent] = await Promise.all([get("/v1/admin/info"), get("/v1/admin/peers"), get("/v1/admin/tokens"),
        info.people && isAdmin() ? get("/v1/admin/people") : null, get("/v1/admin/audit?limit=8").catch(() => null)]);
      renderOverview();
      renderRecent(recent);
    } else if (t === "people") {
      [peers, idp] = await Promise.all([get("/v1/admin/peers"), info.people && isAdmin() ? get("/v1/admin/people") : null]);
      renderPeople();
    } else if (t === "devices") {
      [peers, tokens, policies, auths, links, idp] = await Promise.all([get("/v1/admin/peers"), get("/v1/admin/tokens"),
        get("/v1/admin/policies"), get("/v1/admin/authorities"), get("/v1/admin/links"), info.people && isAdmin() ? get("/v1/admin/people") : null]);
      renderDevices();
      renderTokens();
    } else if (t === "groups") {
      [policies, peers, tokens, links, idp, signin] = await Promise.all([get("/v1/admin/policies"), get("/v1/admin/peers"),
        get("/v1/admin/tokens"), get("/v1/admin/links"), info.people && isAdmin() ? get("/v1/admin/people") : null,
        info.people && isAdmin() ? get("/v1/admin/signin") : null]);
      renderGroupsPage();
    } else if (t === "access") {
      [policies, peers, checks, tokens, links, routes, idp] = await Promise.all([get("/v1/admin/policies"), get("/v1/admin/peers"),
        get("/v1/admin/posture"), get("/v1/admin/tokens"), get("/v1/admin/links"), isAdmin() ? get("/v1/admin/routes") : [],
        info.people && isAdmin() ? get("/v1/admin/people") : null]);
      renderAccess();
    } else if (t === "routes") {
      [routes, policies, peers] = await Promise.all([get("/v1/admin/routes"), get("/v1/admin/policies"), get("/v1/admin/peers")]);
      renderRoutes();
    } else if (t === "names") {
      [dns, peers] = await Promise.all([get("/v1/admin/dns"), get("/v1/admin/peers")]);
      renderNames();
    } else if (t === "links") {
      [links, auths, peers, checks] = await Promise.all([get("/v1/admin/links"), get("/v1/admin/authorities"), get("/v1/admin/peers"),
        get("/v1/admin/posture")]);
      renderLinks();
    } else if (t === "activity") {
      await loadActivity(auto);
    }
    renderNavCount();
    $("foot").textContent = `${info.node} · ento ${info.version || "?"} · updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    if (e.status === 401) signedOut();
    else if (e.status === 403) {
      signedOut();
      notice("This device is neither an administrator nor an operator of the network. Use one that is (for example after signing in with such an account).");
    } else notice("Could not load: " + e.message);
  }
}

// --- opening the page -----------------------------------------------------------------------------
// signedOut shows the code to approve in place of the page, and waits for the approval.
function signedOut() {
  info = null;
  $("app").hidden = true;
  $("signin").hidden = false;
  $("signin-foot").textContent = location.hostname + " · reachable only inside the network";
  if (!pairing) pair();
}

let pairing = null; // the timer that asks whether the code was approved

// On an Android phone the approval is the ento app's (it holds the device's key), so the page says
// that first and keeps the commands for computers below; only the wording changes, not what counts.
const onPhone = /Android/i.test(navigator.userAgent);

// The network's sign-in opens the page too (0.49), for the person signed in on this device in ento.
function showSignIn(st) {
  $("signin-sso").hidden = !st.sign_in;
  if (!st.sign_in) return;
  const go = $("signin-sso-go");
  go.hidden = !st.person;
  go.textContent = st.person ? `Sign in as ${st.person}` : "Sign in";
  $("signin-sso-hint").textContent = st.person
    ? "With your passkey, at this network's sign-in. The page then stays open while you are signed in on this device."
    : "Nobody is signed in on this device. Sign in on it first (sudo ento agent login, or the app), then reload this page.";
}

function showCode(code) {
  $("signin-phone").hidden = !onPhone;
  const [a, b] = (code || "····-····").split("-");
  put($("signin-code"), el("span", {}, a || ""), el("i", { "aria-hidden": "true" }, "·"), el("span", {}, b || ""));
  $("signin-code").setAttribute("aria-label", "Code " + code);
  $("signin-cmd").textContent = `sudo ento admin ui ${code}`;
}

async function pair() {
  clearInterval(pairing);
  pairing = true; // asking: no second pairing meanwhile
  try {
    const st = await call("POST", "/ui/session");
    if (st.state === "open") { opened(); return; }
    showSignIn(st);
    showCode(st.code);
  } catch (e) {
    notice("Could not get a code: " + e.message);
  }
  pairing = setInterval(waitApproval, 2000);
}

async function waitApproval() {
  if (document.hidden) return;
  let st;
  try { st = await call("GET", "/ui/session"); } catch (e) { return; }
  if (st.state === "open") opened();
  else if (st.state === "none") { clearInterval(pairing); pair(); } // the code expired: a new one
  else { showSignIn(st); showCode(st.code); }
}

function opened() {
  clearInterval(pairing);
  pairing = null;
  notice("");
  $("signin").hidden = true;
  show();
}

$("sign-out").addEventListener("click", async () => {
  try { await call("DELETE", "/ui/session"); } catch (e) { /* the session ends either way */ }
  notice("");
  signedOut();
});

// Operators administer within limits (ordinary devices, ordinary tokens, policies); the API enforces
// them, the page only leaves out what they cannot do.
const isAdmin = () => !!(info && info.self.admin);
// A role takes a person in admins or operators signed in on a device in admin or operator (0.54):
// roleOf is what the device has now, deviceRole its own group's role, hasRole either layer's.
const roleOf = (p) => p.admin ? "admin" : (p.operator ? "operator" : null);
const deviceRole = (p) => (ownGroups(p).includes(DEV + "admin") ? "admin" : (ownGroups(p).includes(DEV + "operator") ? "operator" : null));
const hasRole = (p) => !!(roleOf(p) || deviceRole(p) || p.person_role);
const mayChange = (p) => isAdmin() || !hasRole(p);
// roleBadge: the role it has now, else its group's, which waits for a person with that role.
const roleBadge = (p) => roleOf(p) ? badge(roleOf(p), "mute")
  : (deviceRole(p) ? badge(`${deviceRole(p)} device`, "mute", { title: `administers once a person in ${deviceRole(p)}s signs in on it` }) : null);

function renderMe() {
  if (!info) return;
  $("signin").hidden = true;
  $("app").hidden = false;
  const s = info.self;
  $("net-name").textContent = pageDomain() || location.hostname;
  $("net-host").textContent = info.network;
  $("me-name").textContent = s.user || s.hostname;
  $("me-device").textContent = `${s.hostname} · ${isAdmin() ? "admin" : (info.viewer ? "viewer" : "operator")}`;
  $("me-avatar").textContent = initials(s.user || s.hostname);
  document.querySelectorAll("[data-admin-only]").forEach((e) => { e.hidden = !isAdmin(); });
  document.body.classList.toggle("viewer", !!info.viewer);
  document.title = `${pageDomain() || "Dashboard"} · entowire`;
}

// A device in isolated is kept apart: it reaches nothing and nothing reaches it (ento 0.43). Giving
// it groups lets it in.
const isIsolated = (p) => (p.machine_groups || p.groups || []).includes("isolated") || (p.groups || []).includes("isolated");
const pendingOf = () => peers.filter((p) => !p.suspended && (isIsolated(p) || !p.approved));
function renderNavCount() {
  const n = pendingOf().length;
  $("nav-waiting").textContent = String(n);
  $("nav-waiting").hidden = !n;
}

// --- devices: what they are -----------------------------------------------------------------------
function kindOf(p) {
  const os = ((p.posture && p.posture.os) || p.os || "").toLowerCase();
  if (/android|ios|iphone/.test(os)) return "phone";
  if (!p.user && /linux|flatcar|debian|ubuntu|fedora|rhel|alpine/.test(os)) return "server";
  return "laptop";
}
const devIcon = (p, cls = "ico sm") => el("span", { class: cls }, icon(kindOf(p)));

// A device fails a posture check that a policy requires of it: those policies leave it out.
const failsPosture = (p) => (p.posture_checks || []).some((r) => r.required && !r.passed);
const systemNames = { linux: "Linux", darwin: "macOS", windows: "Windows", android: "Android" };

function systemOf(p) {
  const f = p.posture;
  if (!f) return p.os || "";
  return [systemNames[f.os] || f.os, f.os_version].filter(Boolean).join(" ") + (f.distribution ? ` (${f.distribution})` : "");
}

// stateOf: the device's approval, as one or two short badges. A device bound to a person has two
// layers: the machine's approval, and the person's session.
function stateOf(p) {
  if (p.suspended && p.clone_suspected) {
    return [badge("Suspended: copied identity?", "bad", { title: `${p.clone_suspected} (${when(p.clone_suspected_at)}); resume once you know why` })];
  }
  if (p.suspended) return [badge("Suspended", "bad")];
  if (isIsolated(p)) return [badge("Isolated", "warn", { title: "Reaches nothing and nothing reaches it: give it groups to let it in" })];
  if (!p.approved) return [badge(p.user && p.login_at ? "Signed out" : "Waiting", "warn")];
  const out = [];
  if (!(p.user && !p.authority && !p.machine_approved)) {
    out.push(badge(p.approved_until ? "Approved " + until(p.approved_until) : "Approved", "ok", { title: p.approved_until ? "until " + when(p.approved_until) : null }));
  }
  if (p.user && !p.authority) {
    out.push(badge(p.person_active ? "Signed in" : "Signed out", p.person_active ? "info" : "mute", {
      title: p.person_active ? `${p.user}'s rights too, since ${when(p.person_since)}` + (p.person_activity_at ? `; last active ${ago(p.person_activity_at)}` : "")
        : `${p.user} is signed out: the device has only its machine's rights` }));
  }
  return out;
}

// checksOf: how the device does on the checks its rules require, in one badge.
function checksOf(p) {
  const required = (p.posture_checks || []).filter((r) => r.required);
  const failing = required.filter((r) => !r.passed);
  if (failing.length) return badge(failing.length === 1 ? `Fails ${failing[0].check}` : `Fails ${failing.length} checks`, "warn", { title: failing.map((r) => `${r.check}: ${r.reason}`).join("\n") });
  if (required.length) return badge("Passed", "ok", { title: required.map((r) => r.check).join(", ") });
  return p.posture ? badge("Reporting", "mute", { title: "reported " + ago(p.posture_reported_at) + "; no rule requires a check of it" }) : badge("No report", "mute");
}

function fact(v, on, off, what) {
  if (v === undefined || v === null) return tag(what + " ?", "tag", { title: "the device could not tell" });
  return v ? badge(on, "ok") : badge(off, "bad");
}

// verifiedBoot shows what a phone's attestation showed, as the control node verified it.
function verifiedBoot(a) {
  if (!a) return badge("Boot not attested", "mute", { title: "the phone sent no attestation (an app older than ento 0.30?)" });
  if (a.error) return badge("Boot not attested", "mute", { title: "the attestation does not count: " + a.error });
  const detail = `attested by the phone's ${a.security_level === "strongbox" ? "StrongBox" : "trusted execution environment"}` +
    `: ${a.boot_state}, bootloader ${a.locked ? "locked" : "unlocked"}` + (a.app ? `; app ${a.app}` : "");
  if (a.boot_state === "verified" && a.locked) return badge("Verified boot", "ok", { title: detail });
  return badge(a.locked ? a.boot_state + " boot" : "Unlocked", "bad", { title: detail });
}

// postureOf: the device's latest report and how it does on each check.
function postureOf(p) {
  const results = (p.posture_checks || []).map((r) => el("div", { class: "box" },
    el("div", { class: "grow" }, el("b", {}, r.check), el("small", {}, (r.passed ? "passes" : "fails: " + r.reason) + (r.required ? " · a rule requires it" : " · no rule requires it"))),
    badge(r.passed ? "Pass" : "Fail", r.passed ? "ok" : (r.required ? "bad" : "mute"))));
  if (!p.posture) return [el("p", { class: "hint" }, "No report from this device yet."), results];
  const f = p.posture;
  const boot = f.os === "android" ? verifiedBoot(f.attested) : fact(f.secure_boot, "Secure Boot", "No Secure Boot", "Secure Boot");
  return [
    el("div", { class: "tags" }, fact(f.disk_encryption, "Encrypted", "Not encrypted", "Encryption"),
      fact(f.firewall, "Firewall", "No firewall", "Firewall"), boot, fact(f.antimalware, "Anti-malware", "No anti-malware", "Anti-malware")),
    el("p", { class: "hint" }, systemOf(p) + (f.patch_level ? `, patch ${f.patch_level}` : "") + " · reported " + ago(p.posture_reported_at) + (f.agent ? " by ento " + f.agent : "")),
    results,
  ];
}

// --- overview -------------------------------------------------------------------------------------
function renderOverview() {
  const on = peers.filter(online).length;
  const pending = pendingOf();
  const failing = peers.filter(failsPosture);
  const people = peopleOf();
  $("ov-sub").textContent = `${pageDomain() || location.hostname}${info.sso ? " · single sign-on" : ""}`;

  const stale = info.controls.filter((c) => !c.last_seen || Date.now() - Date.parse(c.last_seen) > 180000);
  put($("health"), 
    el("div", { class: "state" }, el("span", { class: "pulse" + (stale.length ? " warn" : ""), "aria-hidden": "true" }),
      el("div", {}, el("b", {}, stale.length ? `${plural(stale.length, "control node")} not heard from lately` : "Everything is running"),
        el("span", {}, `${info.node} answers · ento ${info.version || "?"}`))),
    el("div", { class: "nodes" }, info.controls.map((c) => el("div", { class: "node" },
      el("span", { class: "dot " + (stale.includes(c) ? "warn" : "on"), "aria-hidden": "true" }),
      el("div", {}, el("b", {}, c.name), el("small", {}, c.name === info.node ? "answering this page" : "seen " + ago(c.last_seen)))))));

  const stat = (k, v, n, href, hot = false) => el(href ? "a" : "div", { class: "card stat" + (hot ? " hot" : ""), href }, el("span", { class: "k" }, k),
    el("span", { class: "v" }, String(v)), el("span", { class: "n" }, n));
  put($("stats"), 
    stat("Devices", peers.length, `${on} online now`, "#devices"),
    stat("People", people.length, idp && people.some((x) => x.idp && x.idp.setup) ? `${people.filter((x) => x.active).length} signed in now · ${people.filter((x) => x.idp && x.idp.setup).length} invited`
      : `${people.filter((x) => x.active).length} signed in now`, "#people"),
    stat("Waiting for you", pending.length, pending.length === 1 ? "device to approve" : "devices to approve", "#devices", pending.length > 0),
    stat("Failing a check", failing.length, failing.length ? "left out of rules that need it" : "every device passes", "#devices", failing.length > 0));

  put($("waiting"), ...list(pending.map((p) => el("div", { class: "item" },
    devIcon(p, "ico"),
    el("div", { class: "who" }, el("b", {}, p.hostname), el("small", {}, [p.user || "no person", systemOf(p), "asked " + ago(p.login_at || p.created_at)].filter(Boolean).join(" · "))),
    failsPosture(p) ? checksOf(p) : null,
    mayChange(p) ? el("div", { class: "row-actions" }, button("Remove", () => remove(p), "btn sm"),
      button("Let in…", () => letIn(p), "btn sm primary")) : null)), "Nobody is waiting."));

  const att = [];
  for (const p of peers.filter((x) => x.suspended && x.clone_suspected)) {
    att.push(attention(p, "Suspended: its identity seemed in use on another machine", p.clone_suspected, "bad"));
  }
  for (const p of failing) {
    const f = (p.posture_checks || []).filter((r) => r.required && !r.passed);
    att.push(attention(p, `Fails ${f.map((r) => r.check).join(", ")}`, f.map((r) => r.reason).join("; "), "warn"));
  }
  for (const p of peers.filter((x) => x.hostname.startsWith(selfPrefix) && x.reported_hostname && !x.suspended)) {
    att.push(attention(p, "Named after its host name", `Confirm ${fromReported(p.reported_hostname)} or rename it`, "mute"));
  }
  put($("attention"), ...list(att, "Nothing needs a look."));

  const s = info.self;
  const facts = [["Overlay", info.network], ["Single sign-on", info.sso ? "on" : "off"], ["People", info.people ? "managed here" : "in the identity provider"], ["Answering", `${info.node} · ento ${info.version || "?"}`],
    ["Control nodes", String(info.controls.length)], ["This device", `${s.hostname} · ${s.address}`]];
  put($("facts"), ...facts.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));

  const own = tokens.filter((t) => !t.authority);
  put($("ov-tokens"), ...(own.length ? own.slice(0, 4).map((t) => el("div", { class: "kv" },
    el("span", {}, t.name || "a device named after its host", (t.groups || []).length ? " · " + t.groups.join(", ") : ""),
    el("span", { title: when(t.expires_at) }, "expires " + until(t.expires_at)))) : [el("p", { class: "hint" }, "None open. Add a device to make one.")]));
}

function attention(p, what, why, kind) {
  return el("div", { class: "item" }, devIcon(p, "ico"),
    el("div", { class: "who" }, el("b", {}, p.hostname), el("small", {}, why || "")),
    badge(what, kind), button("Open", () => { openDevice(p.id); }, "btn sm"));
}

// --- people ---------------------------------------------------------------------------------------
// People come from two places: the identity provider, when the control nodes manage it (info.people:
// everyone, invited ones too, with their groups, passkeys and whether they are enabled), and the
// devices, which know who signed in on them (their sign-in's groups, whether they are signed in now).
let idp = null; // the provider's people (api.PeopleList), when managed here
const personCache = new Map(); // id → the provider's person with passkeys

function deviceUsers() {
  const by = new Map();
  for (const p of peers) {
    if (!p.user || p.authority) continue;
    if (!by.has(p.user)) by.set(p.user, { devices: [], groups: new Set(), roles: new Set() });
    const x = by.get(p.user);
    x.devices.push(p);
    (p.person_groups || []).forEach((g) => x.groups.add(g));
    if (p.person_role) x.roles.add(p.person_role);
  }
  return by;
}

const displayName = (pp) => [pp.given_name, pp.family_name].filter(Boolean).join(" ") || pp.email;

// peopleOf: one entry per person, the provider's merged with what their devices know (matched by
// the name devices show, usually the e-mail address).
function peopleOf() {
  const users = deviceUsers();
  const out = [];
  const fromDevices = (key) => {
    const x = users.get(key);
    users.delete(key);
    return x || { devices: [], groups: new Set(), roles: new Set() };
  };
  const entry = (key, name, email, user, pp, x) => ({
    key, name, email, user, idp: pp, devices: x.devices,
    groups: pp ? pp.groups : [...x.groups].sort(),
    role: roleFromGroups(pp ? pp.groups : [...x.groups]) || (x.roles.has("admin") ? "admin" : (x.roles.has("operator") ? "operator" : null)),
    active: x.devices.some((p) => p.person_active),
    suspended: x.devices.length > 0 && x.devices.every((p) => p.suspended),
    last: latest(pp && pp.last_login, ...x.devices.map((p) => p.person_activity_at || p.last_seen)),
  });
  if (idp) {
    for (const pp of idp.people) {
      const key = [...users.keys()].find((u) => u.toLowerCase() === pp.email.toLowerCase()) || pp.email;
      out.push(entry(pp.id, displayName(pp), pp.email, key, pp, fromDevices(key)));
    }
  }
  for (const [user] of [...users]) out.push(entry("dev:" + user, user, user.includes("@") ? user : "", user, null, fromDevices(user)));
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// roleFromGroups: a person's role, from their people groups (the groups that give each role).
function roleFromGroups(groups) {
  const r = (info && info.person_roles) || {};
  for (const role of ["admin", "operator", "viewer"]) if ((r[role] || []).some((g) => groups.includes(g))) return role;
  return null;
}

function statusOf(x) {
  if (x.idp && !x.idp.enabled) return badge("Disabled", "bad");
  if (x.idp && x.idp.setup) return badge("Invited", "warn", { title: "No passkey yet: a setup link lets them in" });
  if (x.suspended) return badge("Suspended", "bad");
  return x.active ? badge("Signed in", "info") : badge(x.idp ? "Active" : "Signed out", "mute");
}

const peopleFilters = [["all", "Everyone", () => true], ["active", "Signed in now", (x) => x.active],
  ["invited", "Invited", (x) => !!(x.idp && x.idp.setup)], ["admin", "Admins and operators", (x) => !!x.role],
  ["off", "Disabled or suspended", (x) => !!(x.idp && !x.idp.enabled) || x.suspended]];

function renderPeople() {
  const people = peopleOf();
  $("people-sub").textContent = idp ? "Everyone in the network's sign-in, and who signed in on which device."
    : "Everyone who signed in on a device of this network.";
  $("person-new").hidden = !idp;
  filterChips($("people-filter"), peopleFilters, people, ui.peopleFilter, (v) => { ui.peopleFilter = v; renderPeople(); });
  const q = $("people-search").value.trim().toLowerCase();
  const test = peopleFilters.find((f) => f[0] === ui.peopleFilter)[2];
  const shown = people.filter((x) => test(x) && (!q || [x.name, x.email, ...x.groups].some((v) => (v || "").toLowerCase().includes(q))));
  const pick = (x) => { ui.person = x.key; renderPeople(); if (x.idp) loadPerson(x.idp.id); };
  const body = $("people-table").tBodies[0];
  put(body, ...(shown.length ? shown.map((x) => el("tr", { class: "pick" + (ui.person === x.key ? " sel" : ""), tabindex: "0",
    onclick: () => pick(x), onkeydown: (e) => { if (e.key === "Enter") pick(x); } },
    el("td", {}, el("div", { class: "cell" }, el("span", { class: "avatar" + (ui.person === x.key ? " lite" : "") }, initials(x.name)),
      el("div", {}, el("b", {}, x.name), x.email && x.email !== x.name ? el("small", {}, x.email) : null))),
    el("td", {}, el("div", { class: "tags" }, x.groups.length ? x.groups.map((g) => tag(g)) : el("span", { class: "dim" }, "–"))),
    el("td", {}, String(x.devices.length)),
    el("td", { class: "dim nowrap", title: when(x.last) }, x.last ? ago(x.last) : "never"),
    el("td", {}, el("div", { class: "tags nowrap" }, statusOf(x), x.role ? badge(x.role, "mute") : null))))
    : [el("tr", {}, el("td", { colspan: 5 }, empty(people.length ? "Nobody matches." : "Nobody yet.")))]));
  renderPerson(people.find((x) => x.key === ui.person));
}

async function loadPerson(id) {
  try {
    personCache.set(id, await call("GET", `/v1/admin/people/${encodeURIComponent(id)}`));
  } catch (e) { notice("Could not load the person: " + e.message); }
  if (tab() === "people") renderPeople();
}

function renderPerson(x) {
  const d = $("person-detail");
  if (!x) {
    put(d, el("div", { class: "dhead" }, el("div", {}, el("b", {}, "People"),
      el("small", {}, "Select a person."))),
      el("p", { class: "hint" }, "Their groups in the network's sign-in decide what their devices reach while they are signed in. " +
        "Disabling a person ends that within minutes, on every device; suspending their devices cuts the devices off too, even their own rights."));
    return;
  }
  const pp = x.idp;
  const full = pp && personCache.get(pp.id);
  const sections = [
    el("div", { class: "dhead" }, el("span", { class: "avatar lg lite" }, initials(x.name)),
      el("div", {}, el("b", {}, x.name), el("small", {}, x.email || (x.role ? x.role : "member"))),
      button(icon("close", 16), () => { ui.person = null; renderPeople(); }, "icon-btn", { "aria-label": "Close" })),
    el("div", { class: "tags" }, statusOf(x), x.role ? badge(x.role, "mute") : null, pp ? null : badge("not in this network's sign-in", "mute")),
    el("div", { class: "sect" }, el("h3", {}, "Groups"),
      el("div", { class: "tags" }, x.groups.length ? x.groups.map((g) => tag(g)) : el("span", { class: "dim" }, "none")),
      pp ? button("Change groups", () => editPersonGroups(pp), "link")
        : el("p", { class: "hint" }, "From their sign-in; devices take them at every sign-in.")),
  ];
  if (pp && full && full.signin) {
    const si = full.signin;
    sections.push(el("div", { class: "sect" }, el("h3", {}, "Sign-in"),
      el("dl", { class: "facts" },
        el("dt", {}, "Has"), el("dd", {}, [si.password ? "password" : null, si.passkeys ? plural(si.passkeys, "passkey") : null, si.totp ? "authenticator app" : null].filter(Boolean).join(", ") || "nothing yet"),
        el("dt", {}, "Allowed"), el("dd", {}, (si.allowed || []).map(methodName).join(", ") || "–"),
        el("dt", {}, "Can use"), el("dd", {}, (si.usable || []).length ? si.usable.map(methodName).join(", ") : badge(pp.setup ? "set up with the link" : "nothing allowed", "warn")))));
  }
  if (pp) {
    const keys = full ? (full.passkeys || []) : null;
    sections.push(el("div", { class: "sect" }, el("h3", {}, "Passkeys"),
      keys === null ? el("p", { class: "hint" }, "Loading…")
        : keys.length ? keys.map((k) => el("div", { class: "box" },
          el("div", { class: "grow" }, el("b", {}, k.name), el("small", {}, `added ${k.registered_at ? new Date(k.registered_at).toLocaleDateString() : "?"} · used ${ago(k.last_used_at)}`)),
          button("Remove", () => removePasskey(pp, k), "btn xs danger")))
        : el("p", { class: "hint" }, pp.setup ? "None yet: they set one up with their setup link." : "None."),
      pp.setup || (full && full.signin && !(full.signin.usable || []).length) ? button("New setup link", () => newSetupLink(pp), "link") : null));
  }
  sections.push(el("div", { class: "sect" }, el("h3", {}, "Devices"),
    x.devices.length ? x.devices.map((p) => el("div", { class: "box" }, devIcon(p),
      el("div", { class: "grow" }, el("b", {}, p.hostname),
        el("small", {}, el("span", { class: "mono" }, p.address), ` · ${online(p) ? "online" : "seen " + ago(p.last_seen)}`),
        el("div", { class: "tags" }, stateOf(p))),
      el("div", { class: "row-actions nowrap" }, p.person_active && mayChange(p) && p.id !== info.self.id ? button("Sign out", () => signOutDevice(p)) : null,
        button("Open", () => openDevice(p.id)))))
      : el("p", { class: "hint" }, "Hasn't joined from any device yet: a device appears here once they sign in on it in ento.")));
  const foot = [];
  if (pp) {
    foot.push(pp.enabled ? button("Disable", () => setEnabled(pp, false), "btn sm danger") : button("Enable", () => setEnabled(pp, true), "btn sm"));
  }
  if (x.devices.length) {
    foot.push(x.suspended ? button("Resume every device", () => suspendUser(x.user, false), "btn sm")
      : button("Suspend every device", async () => {
        if (await confirmTyped(`Suspend every device of ${x.name}?`, "Each device they signed in on loses access at once, its own rights too: for someone who leaves. Signing in again does not restore it; only resuming does.",
          x.email || x.user, "Suspend")) suspendUser(x.user, true);
      }, "btn sm danger"));
  }
  if (pp) foot.push(button("Delete", () => deletePerson(pp), "link danger"));
  if (foot.length) sections.push(el("div", { class: "dfoot" }, foot));
  put(d, ...sections);
}

async function personChange(pp, change, done) {
  try {
    await call("PATCH", `/v1/admin/people/${encodeURIComponent(pp.id)}`, change);
    notice(`${displayName(pp)} ${done}.`, true);
  } catch (e) { notice(`${displayName(pp)}: ${e.message}`); }
  personCache.delete(pp.id);
  load();
  if (ui.person === pp.id) loadPerson(pp.id);
}

// confirmTyped asks twice for what cannot be taken back lightly: a confirmation, then the name typed.
async function confirmTyped(title, text, name, ok) {
  if (!await ask(title, text, { ok, danger: true })) return false;
  const typed = await ask(`Type ${name} to confirm`, "", { input: "", ok, danger: true });
  if (typed === null) return false;
  if (typed.trim().toLowerCase() !== name.toLowerCase()) { notice("That was not " + name + ": nothing changed."); return false; }
  return true;
}

async function setEnabled(pp, on) {
  if (!on && !await confirmTyped(`Disable ${displayName(pp)}?`, "They cannot sign in any more, and their devices lose what their sign-in gives them within minutes. Their devices keep their machines' own rights: suspend those too for someone who leaves.",
    pp.email, "Disable")) return;
  personChange(pp, { enabled: on }, on ? "enabled" : "disabled");
}

async function editPersonGroups(pp) {
  const pick = picker(pp.groups, peopleGroupList);
  if (!await ask(`Groups of ${displayName(pp)}`, "Their devices take them at their next sign-in or refresh (within minutes). Rules on the Access page decide what each group reaches.",
    { body: pick.el, ok: "Save" })) return;
  personChange(pp, { groups: pick.values() }, "updated");
}

async function removePasskey(pp, k) {
  if (!await ask(`Remove passkey ${k.name}?`, `${displayName(pp)} cannot sign in with it any more. For a lost key: once none is left, a new setup link lets them register another.`,
    { ok: "Remove", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/people/${encodeURIComponent(pp.id)}/passkeys/${encodeURIComponent(k.name)}`);
    notice(`Passkey ${k.name} removed.`, true);
  } catch (e) { notice(`${k.name}: ${e.message}`); }
  personCache.delete(pp.id);
  load();
  loadPerson(pp.id);
}

async function deletePerson(pp) {
  if (!await confirmTyped(`Delete ${displayName(pp)}?`, "They are removed from the network's sign-in, with their passkeys. Their devices keep their machines' own rights: suspend those first for someone who leaves.",
    pp.email, "Delete")) return;
  try {
    await call("DELETE", `/v1/admin/people/${encodeURIComponent(pp.id)}`);
    notice(`${displayName(pp)} deleted.`, true);
    ui.person = null;
  } catch (e) { notice(`${displayName(pp)}: ${e.message}`); }
  load();
}

async function newSetupLink(pp) {
  try {
    showSetupLink(displayName(pp), await call("POST", `/v1/admin/people/${encodeURIComponent(pp.id)}/setup`));
  } catch (e) { notice(`${displayName(pp)}: ${e.message}`); }
}

// showSetupLink shows a person's setup link once, to hand over: nobody mails it.
function showSetupLink(name, link) {
  const box = el("div", { class: "stack" },
    el("pre", { class: "secret" }, link.link),
    el("p", { class: "hint" }, `Valid until ${when(link.expires_at)}, for one setup. Send it to ${name} the way you trust (a chat they are signed in to, in person): ` +
      "whoever opens it first registers the passkey of this account. A new link replaces this one."),
    button("Copy link", async () => {
      try { await navigator.clipboard.writeText(link.link); notice("Link copied.", true); }
      catch { notice("Copy it by hand: the browser did not allow copying."); }
    }, "btn sm"));
  ask(`Setup link for ${name}`, "", { body: box, ok: "Done" });
}

$("person-new").addEventListener("click", async () => {
  const email = el("input", { class: "input", type: "email", autocomplete: "off", placeholder: "name@example.com", "aria-label": "E-mail address", required: true });
  const given = el("input", { class: "input", autocomplete: "off", placeholder: "Given name", "aria-label": "Given name" });
  const family = el("input", { class: "input", autocomplete: "off", placeholder: "Family name", "aria-label": "Family name" });
  const pick = picker(idp && idp.groups.includes("users") ? ["users"] : [], peopleGroupList);
  const body = el("div", { class: "stack" },
    el("label", { class: "field" }, el("span", {}, "E-mail address"), email),
    el("div", { class: "fields" }, el("label", { class: "field" }, el("span", {}, "Given name"), given), el("label", { class: "field" }, el("span", {}, "Family name"), family)),
    el("div", { class: "field" }, el("span", {}, "Groups"), pick.el));
  if (!await ask("Invite a person", "They get a setup link to register a passkey; you hand it over.", { body, ok: "Invite" })) return;
  try {
    const r = await call("POST", "/v1/admin/people", { email: email.value.trim(), given_name: given.value.trim() || undefined,
      family_name: family.value.trim() || undefined, groups: pick.values() });
    ui.person = r.person.id;
    load();
    showSetupLink(displayName(r.person), r.setup);
  } catch (e) { notice("Invite: " + e.message); }
});

$("people-search").addEventListener("input", renderPeople);

function filterChips(box, filters, items, current, pick) {
  put(box, ...filters.map(([v, label, test]) => el("button", { type: "button", class: "chip", "aria-pressed": String(v === current), onclick: () => pick(v) },
    label, el("span", {}, String(items.filter(test).length)))));
}

// --- devices --------------------------------------------------------------------------------------
const deviceFilters = [["all", "All", () => true], ["online", "Online", online], ["pending", "Isolated", (p) => !p.suspended && (isIsolated(p) || !p.approved)],
  ["posture", "Failing a check", failsPosture], ["suspended", "Suspended", (p) => p.suspended], ["admin", "Admins", hasRole]];

function openDevice(id) {
  ui.device = id;
  if (tab() === "devices") renderDevices();
  else location.hash = "#devices";
}

function renderDevices() {
  const pending = pendingOf().length;
  $("dev-sub").textContent = `${plural(peers.length, "device")} · ${peers.filter(online).length} online` + (pending ? ` · ${pending} waiting for you` : "");
  filterChips($("device-filter"), deviceFilters, peers, ui.deviceFilter, (v) => { ui.deviceFilter = v; renderDevices(); });
  const q = $("device-search").value.trim().toLowerCase();
  const test = deviceFilters.find((f) => f[0] === ui.deviceFilter)[2];
  const shown = peers.filter((p) => test(p) && (!q || [p.hostname, p.reported_hostname, p.user, p.address, p.os, p.endpoint, p.authority, ...(p.groups || [])]
    .some((x) => (x || "").toLowerCase().includes(q))));
  const body = $("device-table").tBodies[0];
  put(body, ...(shown.length ? shown.map((p) => {
    const machineApproved = p.authority || !p.user ? p.approved : p.machine_approved;
    const pick = () => { ui.device = p.id; renderDevices(); };
    return el("tr", { class: "pick" + (ui.device === p.id ? " sel" : "") + (!p.approved && !p.suspended ? " wait" : ""), tabindex: "0", onclick: pick,
      onkeydown: (e) => { if (e.key === "Enter") pick(); } },
      el("td", {}, el("div", { class: "cell" }, devIcon(p), el("div", {}, el("b", {}, p.hostname, p.id === info.self.id ? el("span", { class: "dim small" }, " · this device") : null),
        el("small", { class: "seen", title: when(p.last_seen) }, el("span", { class: "dot" + (online(p) ? " on" : "") }), online(p) ? "online" : "seen " + ago(p.last_seen), systemOf(p) ? " · " + systemOf(p) : "")))),
      el("td", {}, p.user || (p.authority ? "via " + p.authority : el("span", { class: "dim" }, "–"))),
      el("td", { class: "mono" }, p.address),
      el("td", {}, el("div", { class: "tags" }, stateOf(p), roleBadge(p))),
      el("td", {}, checksOf(p)),
      el("td", { class: "right" }, (isIsolated(p) || !machineApproved) && !p.suspended && mayChange(p) ? button("Let in…", () => letIn(p), "btn xs primary") : null));
  }) : [el("tr", {}, el("td", { colspan: 6 }, empty("No devices match.")))]));
  renderDeviceSide();
}

// The panel beside the table: a device's details, or nothing (the table takes the width).
function renderDeviceSide() {
  const p = peers.find((x) => x.id === ui.device);
  $("device-side").hidden = !p;
  $("device-split").classList.toggle("solo", !p);
  $("device-detail").hidden = !p;
  if (p) renderDeviceDetail(p);
}

function renderDeviceDetail(p) {
  const me = p.id === info.self.id;
  const machineApproved = p.authority || !p.user ? p.approved : p.machine_approved;
  const acts = [];
  if (mayChange(p)) {
    if (p.suspended) acts.push(button("Resume", () => resume(p), "btn sm"));
    else {
      if (isIsolated(p) || !machineApproved) acts.push(button("Let in…", () => letIn(p), "btn sm primary",
        { title: p.user ? "The machine's approval: it stays connected with its own groups when nobody is signed in" : null }));
      else if (!me) acts.push(button("Isolate", () => unapprove(p), "btn sm"));
      if (p.person_active && !me) acts.push(button("Sign out " + (p.user || ""), () => signOutDevice(p), "btn sm"));
      if (!me) acts.push(button("Suspend", () => suspend(p), "btn sm danger"));
    }
  }
  const edits = [];
  if (p.hostname.startsWith(selfPrefix) && p.reported_hostname) {
    edits.push(button(`Confirm ${fromReported(p.reported_hostname)}`, () => setName(p, { use_reported_hostname: true }), "link", { title: "Rename it after the host name it reported" }));
  }
  if (mayChange(p)) edits.push(button("Rename", () => rename(p), "link"), button("Change groups", () => editGroups(p), "link"));
  if (isAdmin() && p.hardware_key) edits.push(button("Release hardware key", () => unbindKey(p), "link"));
  if (!me && isAdmin()) edits.push(button("Delete", () => remove(p), "link danger"));

  const facts = [["Address", p.address], ["Endpoint", p.endpoint || "–"], ["Person", p.user || "–"], ["Host name", p.reported_hostname || "–"],
    ["Joined", when(p.created_at) || "–"], ["Last seen", ago(p.last_seen)], ["Key", p.hardware_key ? `held by ${p.hardware_key.toUpperCase()}` : "in software"]];
  if (p.authority) facts.splice(3, 0, ["Admitted by", p.authority]);
  const person = (p.person_groups || []).filter((g) => !ownGroups(p).includes(g));
  put($("device-detail"), 
    el("div", { class: "dhead" }, devIcon(p, "ico"), el("div", {}, el("b", {}, p.hostname), el("small", {}, systemOf(p) || "–", me ? " · this device" : "")),
      button(icon("close", 16), () => { ui.device = null; renderDevices(); }, "icon-btn", { "aria-label": "Close" })),
    el("div", { class: "tags" }, stateOf(p), roleBadge(p)),
    acts.length ? el("div", { class: "row-actions" }, acts) : null,
    el("div", { class: "sect" }, el("h3", {}, "Groups"),
      el("div", { class: "tags" }, ownGroups(p).map((g) => groupTag(g)), person.map((g) => tag(g, "tag person" + (p.person_active ? "" : " closed"),
        { title: `from ${p.user}'s sign-in` + (p.person_active ? "" : ": not now, they are signed out") })),
        !ownGroups(p).length && !person.length ? el("span", { class: "dim" }, "none") : null),
      managedBy(p) ? el("p", { class: "hint" }, `Set by ${managedBy(p)}.`) : null),
    el("div", { class: "sect" }, el("h3", {}, "Device checks"), postureOf(p)),
    el("div", { class: "sect" }, el("h3", {}, "About"), el("dl", { class: "facts" }, facts.flatMap(([k, v]) => [el("dt", {}, k), el("dd", { class: k === "Address" || k === "Endpoint" ? "mono" : null }, v)]))),
    edits.length ? el("div", { class: "dfoot" }, edits) : null);
}

$("device-search").addEventListener("input", renderDevices);

async function update(p, change, done) {
  try {
    await call("PATCH", `/v1/admin/peers/${p.id}`, change);
    notice(`${p.hostname} ${done}.`, true);
  } catch (e) { notice(`${p.hostname}: ${e.message}`); }
  load();
}

async function setName(p, change) {
  try {
    const r = await call("PATCH", `/v1/admin/peers/${p.id}`, change);
    notice(`${p.hostname} is now ${r.hostname}.`, true);
    if (p.id === info.self.id) info = null; // the frame shows this device's name
  } catch (e) { notice(`${p.hostname}: ${e.message}`); }
  load();
}

async function rename(p) {
  const suggested = p.hostname.startsWith(selfPrefix) && p.reported_hostname ? fromReported(p.reported_hostname) : p.hostname;
  const v = await ask(`Rename ${p.hostname}`, `Lowercase letters, digits and dashes, at most 32 characters. Names starting with ${selfPrefix} are for devices named after their host name.`,
    { input: suggested, ok: "Rename" });
  if (v === null || v.trim() === p.hostname) return;
  setName(p, { hostname: v.trim() });
}

// The other devices the same person signed in on (this network's own sign-ins, not linked ones).
function devicesOf(p, wanted) {
  if (!p.user || p.authority) return [];
  return peers.filter((o) => o.id !== p.id && o.user === p.user && !o.authority && o.id !== info.self.id && mayChange(o) && wanted(o));
}

// Suspending a device offers to suspend every device of its person too, which is what someone
// leaving calls for.
async function suspend(p) {
  const others = devicesOf(p, (o) => !o.suspended);
  const all = el("input", { type: "checkbox" });
  const body = others.length ? el("label", { class: "check" }, all, el("span", {},
    `Also ${others.length === 1 ? "the other device" : `the ${others.length} other devices`} of ${p.user}`, el("small", {}, `${few(others.map((o) => o.hostname))}: for someone who leaves`))) : null;
  if (!await ask(`Suspend ${p.hostname}?`, "It loses access to the network at once. Signing in again does not restore it; only resuming it here does.",
    { body, ok: "Suspend", danger: true })) return;
  if (all.checked) suspendUser(p.user, true);
  else update(p, { suspended: true }, "suspended");
}

async function resume(p) {
  const others = devicesOf(p, (o) => o.suspended);
  if (!others.length) return update(p, { suspended: false }, "resumed");
  const all = el("input", { type: "checkbox" });
  if (!await ask(`Resume ${p.hostname}?`, `It can sign in again; ${p.user} signs in on it to reach the network.`,
    { body: el("label", { class: "check" }, all, el("span", {}, `Also the other suspended devices of ${p.user}`, el("small", {}, few(others.map((o) => o.hostname))))), ok: "Resume" })) return;
  if (all.checked) suspendUser(p.user, false);
  else update(p, { suspended: false }, "resumed");
}

async function suspendUser(user, suspended) {
  try {
    const r = await call("POST", "/v1/admin/users/suspension", { user, suspended });
    const verb = suspended ? "suspended" : "resumed";
    const left = r.skipped.length ? `; left as they were: ${r.skipped.map((d) => `${d.hostname} (${d.reason})`).join(", ")}` : "";
    notice(`${plural(r.changed.length, "device")} of ${user} ${verb}${left}.`, true);
  } catch (e) { notice(`${user}: ${e.message}`); }
  load();
}

// Withdraws the machine's approval: the device waits for an administrator's Approve; one bound to a
// person keeps what their sign-in gives it, while they are signed in. Suspend is the stronger cut.
// letIn gives an isolated device its groups, which lets it in.
async function letIn(p) {
  const pick = picker(ownGroups(p).filter((g) => !/^(device:)?isolated$/.test(g)).map(gname), () => deviceGroupList().filter((g) => g !== DEV + "isolated").map(gname));
  if (!await ask(`Let ${p.hostname} in`, "Its groups decide what it reaches (rules on the Access page) and its role (admins, operators). At least one.", { body: pick.el, ok: "Let in" })) return;
  const groups = pick.values().filter((g) => g !== "isolated");
  if (!groups.length) return notice("Choose at least one group.");
  update(p, { groups }, "is in");
}

async function unapprove(p) {
  if (!await ask(`Isolate ${p.hostname}?`,
    p.user ? `Without anyone signed in it reaches nothing; while ${p.user} is, it has their rights. To keep it out entirely, use Suspend.`
      : "It reaches nothing until an administrator approves it again.",
    { ok: "Isolate", danger: true })) return;
  update(p, { approved: false }, "unapproved");
}

// Ends the person's session on the device: their rights there end until they sign in again (or
// approve a sign-in on it); the machine's stay.
async function signOutDevice(p) {
  if (!await ask(`Sign ${p.user} out of ${p.hostname}?`,
    `${p.user}'s rights on it end until they sign in again. The machine keeps its own. To keep them out even then, use Suspend.`,
    { ok: "Sign out", danger: true })) return;
  update(p, { sign_out: true }, "signed out");
}

async function unbindKey(p) {
  if (!await ask(`Release the hardware key of ${p.hostname}?`,
    "Its next hardware key binds instead: for a device whose TPM was cleared or replaced. Until then, check-ins signed by another key are refused.",
    { ok: "Release", danger: true })) return;
  update(p, { unbind_hardware_key: true }, "has no hardware key bound");
}

async function editGroups(p) {
  const by = managedBy(p);
  const pick = picker(ownGroups(p).map(gname), () => deviceGroupList().map(gname));
  const person = (p.person_groups || []).length ? ` ${p.user}'s sign-in adds ${p.person_groups.join(", ")} while they are signed in.` : "";
  const text = by ? `Its groups are set by ${by}: a change here lasts until the next credential.`
    : "The machine's own groups, whoever is signed in. Rules on the Access page decide what each group reaches." + person;
  if (!await ask(`Groups of ${p.hostname}`, text, { body: pick.el, ok: "Save" })) return;
  update(p, { groups: pick.values() }, "updated");
}

async function changeRole(p) {
  const current = deviceRole(p) || "none";
  const choices = [["none", "None", "an ordinary device"],
    ["operator", "Operator", "ordinary devices, invitations and rules; nothing that cannot be undone"],
    ["admin", "Administrator", "everything on this dashboard"]];
  const body = el("div", { class: "stack" }, ...choices.map(([v, label, what]) =>
    el("label", { class: "check" }, el("input", { type: "radio", name: "role", value: v, checked: v === current }), el("span", {}, label, el("small", {}, what)))));
  const how = "A role takes both: a person in admins (or operators) signed in on a device in admin (or operator). With nobody signed in, the device administers nothing.";
  if (!await ask(`Role of ${p.hostname}`, `The device's role. ${how}`, { body, ok: "Save" })) return;
  const role = body.querySelector("input:checked").value;
  if (role === current) return;
  update(p, { admin: role === "admin", operator: role === "operator" }, role === "none" ? "has no role" : `is now ${role === "admin" ? "an administrator" : "an operator"}`);
}

async function remove(p) {
  if (!await ask(`Remove ${p.hostname}?`, "The device leaves the network. To come back it needs a new invitation.", { ok: "Remove", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/peers/${p.id}`);
    notice(`${p.hostname} removed.`, true);
    if (ui.device === p.id) ui.device = null;
  } catch (e) { notice(`${p.hostname}: ${e.message}`); }
  load();
}

// --- invitations (enrollment tokens) --------------------------------------------------------------
let tokenKind = "words";
const kindHints = {
  words: "For people's computers, phones and Windows: read out five words, or show the QR code to the phone. At most 1 day.",
  file: "For servers and automation on Linux or macOS: a token saved as a file on the device.",
};
function setTokenKind(k) {
  tokenKind = k;
  document.querySelectorAll("#token-form .seg button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.kind === k)));
  $("token-kind-hint").textContent = kindHints[k];
  const ttl = $("token-form").elements.ttl;
  ttl.querySelector("[data-file]").hidden = k === "words";
  if (k === "words" && Number(ttl.value) > 86400) ttl.value = "86400";
}
document.querySelectorAll("#token-form .seg button").forEach((b) => b.addEventListener("click", () => setTokenKind(b.dataset.kind)));

// Add a device: the invitation form in a dialog over the page, then the invitation it made.
function showAddDevice() {
  $("token-result").hidden = true;
  $("token-form").hidden = false;
  if (!$("add-dialog").open) $("add-dialog").showModal();
  drawTokenGroups();
}
$("add-device").addEventListener("click", showAddDevice);
$("add-close").addEventListener("click", () => $("add-dialog").close());
document.querySelectorAll("[data-add-device]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); showAddDevice(); }));

function renderTokens() {
  const body = $("token-table").tBodies[0];
  put(body, ...(tokens.length ? tokens.map((t) => el("tr", {},
    el("td", { class: "mono" }, "#" + t.id),
    el("td", {}, t.name ? el("b", {}, t.name) : el("span", { class: "dim" }, t.authority ? `${t.authority}-<its name at home>` : "from its host name"),
      t.replace ? el("div", { class: "dim small" }, "replaces the device with this name") : null),
    el("td", {}, el("div", { class: "tags" }, (t.groups || []).map((g) => groupTag(g)))),
    el("td", {}, el("div", { class: "tags" }, t.approve ? badge("approved", "ok") : badge("waits for approval", "mute"), t.admin ? badge("admin", "warn") : null)),
    el("td", {}, t.authority ? "authority " + t.authority : madeBy(t.created_by)),
    el("td", { title: when(t.expires_at) }, until(t.expires_at)),
    el("td", { class: "right" }, t.authority ? authorityActions(auths.find((a) => a.name === t.authority) || { name: t.authority })
      : button("Revoke", () => revoke(t), "btn xs danger"))))
    : [el("tr", {}, el("td", { colspan: 7 }, empty("No open invitations.")))]));
}

// madeBy names who made an invitation: the person on the device, else the device.
function madeBy(label) {
  const m = /^peer (\d+) (\S+)/.exec(label || "");
  if (!m) return label || "–";
  const p = peers.find((x) => x.id === Number(m[1]));
  return (p && p.user) || (p ? p.hostname : m[2]);
}

async function revoke(t) {
  if (!await ask(`Revoke invitation #${t.id}?`, "Nobody can join with it any more.", { ok: "Revoke", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/tokens/${t.id}`);
    notice(`Invitation #${t.id} revoked.`, true);
  } catch (e) { notice(`Invitation #${t.id}: ${e.message}`); }
  load();
}

// The invitation's groups: picked from the network's groups (made on the Access page), not typed.
const tokenGroups = new Set();
function drawTokenGroups() {
  // Every device group, isolated too (the device then joins kept apart until let in); authority
  // groups are the authority's to give. A role group gives the device that role: admins only
  // (the control plane refuses it from operators).
  const roles = [DEV + "admin", DEV + "operator"];
  const all = deviceGroupList().filter((g) => g.startsWith(DEV) && (isAdmin() || !roles.includes(g)));
  [...tokenGroups].forEach((g) => { if (!all.includes(g)) tokenGroups.delete(g); });
  put($("token-groups"), ...(all.length ? all.map((g) => el("button", { type: "button", class: "chip", "aria-pressed": String(tokenGroups.has(g)),
    onclick: () => { tokenGroups.has(g) ? tokenGroups.delete(g) : tokenGroups.add(g); drawTokenGroups(); } }, gname(g)))
    : [el("p", { class: "hint" }, "No groups yet: make them on the Access page.")]));
  const none = tokenGroups.size === 0;
  $("token-form").querySelector('button[type="submit"]').disabled = none;
  $("token-need-group").hidden = !none;
}

// pageDomain is the domain whose _ento TXT record names the network: the page's own name is
// net.<domain> ("" when it is not; the control nodes' --record-domain then, if they have one).
function pageDomain() {
  const host = location.hostname;
  return host.startsWith("net.") ? host.slice(4) : "";
}

$("token-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const groups = [...tokenGroups];
  if (!groups.length) { notice("Choose at least one group: it decides what the device reaches."); return; }
  const words = tokenKind === "words";
  if (words && Number(f.ttl.value) > 86400) { notice("Words are good for at most 1 day: choose a shorter time."); return; }
  try {
    const r = await call("POST", "/v1/admin/tokens", { groups,
      ttl_seconds: Number(f.ttl.value), words, qr_domain: words ? pageDomain() : undefined });
    showTokenResult(r, words);
    f.reset();
    setTokenKind(tokenKind);
    tokenGroups.clear();
    load();
  } catch (e) { notice("Could not make the invitation: " + e.message); }
});

function showTokenResult(r, words) {
  const domain = pageDomain() || "DOMAIN";
  const done = button("Done", () => $("add-dialog").close(), "btn sm primary");
  const copy = (text, what) => button("Copy " + what, async () => {
    try { await navigator.clipboard.writeText(text); notice(`${what[0].toUpperCase() + what.slice(1)} copied.`, true); }
    catch { notice("Copy it by hand: the browser did not allow copying."); }
  }, "btn sm");
  const head = el("div", { class: "dhead" }, el("div", {}, el("b", {}, "Give this to the device's owner"),
    el("small", {}, "Shown only now. One device can use it until " + when(r.expires_at) + ".")));
  let body;
  if (words) {
    body = [
      el("div", { class: "step" }, el("p", {}, el("b", {}, "1."), " On the device, run"),
        command(`curl -fsSL https://entowire.com/install.sh | sudo ENTO_JOIN=${domain} sh`),
        el("p", { class: "hint" }, "Or, with ento already there: ", el("code", {}, `sudo ento agent install --join ${domain}`), ". Windows: the same in a PowerShell run as administrator, without sudo.")),
      el("div", { class: "step" }, el("p", {}, el("b", {}, "2."), " It shows the network's fingerprint first: it must be ", el("span", { class: "fingerprint" }, r.fingerprint || "?"), ". If not, stop."),
        el("p", {}, el("b", {}, "3."), " When it asks, type these five words"),
        el("div", { class: "words" }, (r.words || "").split(/\s+/).filter(Boolean).map((w) => el("span", {}, w)))),
      r.qr_svg ? el("div", { class: "step" }, el("p", {}, "A phone in front of you scans this instead (Scan the QR code in the app). It holds the words: never send a picture of it."),
        el("img", { class: "qr", src: "data:image/svg+xml;base64," + btoa(r.qr_svg), alt: "The domain, the network's fingerprint and the words as a QR code", width: "200", height: "200" })) : null,
      el("div", { class: "row-actions" }, copy(r.words || "", "words"), done),
    ];
  } else {
    body = [
      el("div", { class: "step" }, el("p", {}, "Save it as a file on the device, then run"),
        command("sudo ento agent install --token-file ./token")),
      el("pre", { class: "secret" }, r.token || ""),
      el("div", { class: "row-actions" }, copy(r.token || "", "token"), done),
    ];
  }
  put($("token-result"), head, ...body);
  $("token-form").hidden = true;
  $("token-result").hidden = false;
}

// --- groups ---------------------------------------------------------------------------------------
// Groups are labels on devices; rules decide which reach which. A device that signs in takes its
// person's groups from the identity provider at every sign-in, a device of an authority from that
// authority.
const managedBy = (p) => p.authority ? `authority ${p.authority}` : null;
// ownGroups: the groups this page sets, the machine's (a device bound to a person also has theirs).
const ownGroups = (p) => p.authority || !p.user ? (p.groups || []) : (p.machine_groups || []);
// lockedBy: why this page cannot change a device's groups, if it cannot.
const lockedBy = (p) => managedBy(p) || (mayChange(p) ? null : "an administrator");

function knownGroups() {
  // Where people are managed here, groups come from the identity provider only.
  if (idp) return [...idp.groups].sort();
  const all = new Set();
  peers.forEach((p) => (p.groups || []).forEach((g) => all.add(g)));
  policies.forEach((p) => [ruleWho(p), ruleOn(p), p.destination].forEach((g) => { if (g && !g.startsWith("*") && !g.startsWith(SVC)) all.add(g); }));
  tokens.forEach((t) => (t.groups || []).forEach((g) => all.add(g)));
  links.forEach((l) => (l.groups || []).forEach((g) => all.add(g)));
  if (idp) idp.groups.forEach((g) => all.add(g));
  all.delete("*");
  return [...all].filter((g) => !g.startsWith("route:")).sort();
}

// Device groups and people groups are kept apart (ento 0.44): a device group's name carries the
// prefix "device:" where it is stored, which the page never shows; people groups have none.
const DEV = "device:";
// isDev: a device group. A rule's plain name (written before groups had kinds, or from the CLI)
// counts as the device group when the identity provider has only that kind.
const isDev = (g) => g.startsWith(DEV) || (g.includes(":") && !g.startsWith("route:")) ||
  (!!idp && !idp.groups.includes(g) && idp.groups.includes(DEV + g));
const gname = (g) => g.startsWith(DEV) ? g.slice(DEV.length) : g;
const deviceGroupList = () => knownGroups().filter(isDev);
const peopleGroupList = () => knownGroups().filter((g) => !isDev(g));
// groupTag shows a group with the mark of its kind.
const groupTag = (g, cls = "tag", attrs = {}) => el("span", { class: cls, ...attrs }, isDev(g) ? icon("laptop", 12) : icon("people", 12), gname(g));

// A rule is who on which devices reaching devices, a route or a forwarded service (ento 0.53). Who
// is a people group or one of these; devices a device group or any device ("" in on).
const SVC = "service:";
const whoNames = { "*": "anyone", "*signed-in": "everyone signed in", "*nobody": "nobody signed in" };
const ruleWho = (p) => p.who ?? p.source;
const ruleOn = (p) => p.on || "";
const whoLabel = (w) => whoNames[w] || gname(w);
const endLabel = (x) => x === "*" ? "every device" : x.startsWith("route:") ? "route " + x.slice(6) : x.startsWith(SVC) ? x.slice(SVC.length) : gname(x);
const ruleText = (p) => `${whoLabel(ruleWho(p))}${ruleOn(p) ? " on " + gname(ruleOn(p)) : ""} ${p.one_way ? "→" : "↔"} ${endLabel(p.destination)}`;

// picker edits a list of groups: tags that can be removed, and an input suggesting the groups the
// network knows; Enter, a comma or choosing a suggestion adds what was typed.
function picker(initial, suggest) {
  const chosen = [...initial];
  const box = el("div", { class: "picker" });
  const dl = el("datalist", { id: "groups-" + Math.random().toString(36).slice(2) });
  const input = el("input", { list: dl.id, placeholder: "add a group", autocomplete: "off", "aria-label": "Add a group" });
  const draw = () => {
    put(box, ...chosen.map((g) => el("span", { class: "tag" }, g,
      el("button", { type: "button", title: `Remove ${g}`, "aria-label": `Remove ${g}`,
        onclick: () => { chosen.splice(chosen.indexOf(g), 1); draw(); input.focus(); } }, "×"))), input, dl);
    put(dl, ...suggest().filter((g) => !chosen.includes(g)).map((g) => el("option", { value: g })));
  };
  const take = () => {
    for (const g of input.value.split(",").map((v) => v.trim()).filter(Boolean)) if (!chosen.includes(g)) chosen.push(g);
    input.value = "";
    draw();
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || (e.key === "," && input.value.trim())) {
      e.preventDefault(); // never submit the form from here
      if (input.value.trim()) { take(); input.focus(); }
    } else if (e.key === "Backspace" && !input.value && chosen.length) {
      chosen.pop(); draw(); input.focus();
    }
  });
  input.addEventListener("keypress", (e) => { if (e.key === "Enter") e.preventDefault(); });
  input.addEventListener("input", (e) => {
    if (input.value.includes(",") || (e.inputType === "insertReplacementText" && suggest().includes(input.value))) {
      take(); input.focus();
    }
  });
  input.addEventListener("blur", () => { if (input.value.trim()) take(); });
  draw();
  return {
    el: box,
    values() { if (input.value.trim()) take(); return [...chosen]; },
    reset() { chosen.length = 0; input.value = ""; draw(); },
  };
}

// devicePicker lists devices with a checkbox each; those whose groups are set elsewhere are shown
// but cannot be picked.
function devicePicker(skip) {
  const box = el("div", { class: "pick-list" });
  const rows = peers.filter((p) => !skip(p)).map((p) => {
    const by = lockedBy(p);
    return el("label", { class: by ? "off" : null, title: by ? `Its groups are set by ${by}` : null },
      el("input", { type: "checkbox", value: String(p.id), disabled: !!by }), p.hostname,
      el("small", {}, [p.user, by ? "set by " + by : null].filter(Boolean).join(" · ")));
  });
  put(box, ...(rows.length ? rows : [el("p", { class: "hint" }, "No other devices.")]));
  return { el: box, chosen: () => [...box.querySelectorAll("input:checked")].map((c) => peers.find((p) => p.id === Number(c.value))) };
}

function renderAccess() {
  renderPolicies();
  renderChecks();
}

// --- sign-in policies ------------------------------------------------------------------------------
let signin = null; // api.SigninPolicy, where people are managed here
const methodNames = { "passkey": "Passkey", "password+passkey": "Password + passkey", "password+totp": "Password + authenticator app" };
const methodName = (m) => methodNames[m] || m;

// methodBoxes: a checkbox for each way of signing in, those given ticked.
function methodBoxes(chosen) {
  const box = el("div", { class: "stack" }, ...signin.methods.map((m) => el("label", { class: "check" },
    el("input", { type: "checkbox", value: m, checked: chosen.includes(m) }), el("span", {}, methodName(m)))));
  return { el: box, chosen: () => [...box.querySelectorAll("input:checked")].map((i) => i.value) };
}

async function saveSignin(body, done) {
  try {
    await call("PUT", "/v1/admin/signin", body);
    notice(done, true);
  } catch (e) { notice(e.message); }
  load();
}

function renderSigninDefault() {
  const card = $("signin-default");
  card.hidden = !signin || !!ui.group;
  if (!signin || ui.group) return;
  const boxes = methodBoxes(signin.default);
  put(card, el("div", { class: "card-head" }, el("h2", { id: "sd-h" }, "Sign-in methods"), el("span", { class: "dim" }, "for people groups without their own")),
    el("div", { class: "card-body" }, boxes.el,
      el("p", { class: "hint" }, "A people group can allow fewer (open it). Someone in several groups may use only what all of them allow. A change that would leave someone without a way in is refused."),
      button("Save", () => saveSignin({ methods: boxes.chosen() }, "Default sign-in methods saved."), "btn sm primary")));
}

// signinSection: a people group's own policy, or the default.
function signinSection(g) {
  if (!signin || isDev(g)) return null;
  const own = signin.groups[g];
  const boxes = methodBoxes(own || signin.default);
  const useOwn = el("input", { type: "checkbox", checked: !!own });
  const sync = () => { boxes.el.hidden = !useOwn.checked; };
  useOwn.addEventListener("change", sync);
  sync();
  return [el("h3", {}, "Sign-in methods"),
    el("p", { class: "hint" }, own ? "Its own: " + own.map(methodName).join(", ") + "." : "The default: " + signin.default.map(methodName).join(", ") + "."),
    el("label", { class: "check" }, useOwn, el("span", {}, "Its own methods", el("small", {}, "Otherwise the default."))), boxes.el,
    button("Save", () => saveSignin({ group: g, methods: useOwn.checked ? boxes.chosen() : null }, `Sign-in methods of ${gname(g)} saved.`), "btn xs primary")];
}

function renderGroupsPage() {
  const names = knownGroups();
  if (ui.group && !names.includes(ui.group)) ui.group = null;
  $("group-count").textContent = plural(names.length, "group");
  const members = (g) => peers.filter((p) => (p.groups || []).includes(g));
  const item = (g) => el("li", {}, el("button", { type: "button", "aria-pressed": String(ui.group === g),
    onclick: () => { ui.group = ui.group === g ? null : g; renderGroupsPage(); } }, el("b", {}, gname(g)),
    el("small", {}, isDev(g) ? plural(members(g).length, "device") : (idp ? plural(groupPeople(g).length, "person", "people") : plural(members(g).length, "device")))));
  const people = names.filter((g) => !isDev(g)), devices = names.filter(isDev);
  put($("group-list"), ...(names.length ? [
    people.length ? el("li", { class: "group-kind" }, icon("people", 14), "People") : null, ...people.map(item),
    devices.length ? el("li", { class: "group-kind" }, icon("laptop", 14), "Devices") : null, ...devices.map(item),
  ].filter(Boolean) : [el("li", {}, empty("No groups yet."))]));
  renderGroupDetail(ui.group, members);
  $("group-none").hidden = !!ui.group;
  renderSigninDefault();
}

function renderGroupDetail(g, members) {
  const box = $("group-detail");
  box.hidden = !g;
  if (!g) return;
  const also = [];
  const n = tokens.filter((t) => (t.groups || []).includes(g)).length;
  if (n) also.push(plural(n, "invitation"));
  links.filter((l) => (l.groups || []).includes(g)).forEach((l) => also.push(`may join ${l.name}`));
  put(box, 
    el("div", { class: "card-head" }, el("h2", {}, gname(g), el("span", { class: "dim small" }, isDev(g) ? (g.startsWith(DEV) ? " · device group" : " · from authority " + g.split(":")[0]) : " · people group")),
      el("div", { class: "row-actions" }, isDev(g) ? button("Add devices", () => addToGroup(g), "btn xs") : null,
        idp && !isDev(g) ? button("Add people", () => addPeopleToGroup(g), "btn xs") : null,
        button("Allow from this group", () => { policySource = g; location.hash = "#access"; }, "btn xs"),
        button(icon("close", 16), () => { ui.group = null; renderGroupsPage(); }, "icon-btn", { "aria-label": "Close" }))),
    el("div", { class: "card-body" },
      isDev(g) || !idp ? [el("h3", {}, "Devices"),
        el("div", { class: "tags" }, members(g).length ? members(g).map((p) => memberTag(p, g)) : el("span", { class: "dim" }, "No devices in it."))] : null,
      idp && !isDev(g) ? [el("h3", {}, "People"), el("div", { class: "tags" }, groupPeople(g).length ? groupPeople(g).map((pp) => el("span", { class: "tag" }, displayName(pp),
        el("button", { type: "button", title: `Remove ${displayName(pp)} from ${gname(g)}`, "aria-label": `Remove ${displayName(pp)} from ${gname(g)}`,
          onclick: () => removePersonFromGroup(pp, g) }, "×"))) : el("span", { class: "dim" }, "Nobody in it."))] : null,
      signinSection(g),
      also.length ? el("p", { class: "hint" }, "Also used by " + also.join(" · ") + ".") : null,
      idp && isAdmin() ? button("Delete this group", () => deleteGroup(g), "link danger") : null,
      null));
}

function memberTag(p, g) {
  const by = lockedBy(p) || (ownGroups(p).includes(g) ? null : `${p.user}'s sign-in`);
  if (by) return tag(p.hostname, "tag person", { title: `Its groups are set by ${by}` });
  return el("span", { class: "tag" }, p.hostname, el("button", { type: "button",
    title: `Remove ${p.hostname} from ${g}`, "aria-label": `Remove ${p.hostname} from ${g}`, onclick: () => removeFromGroup(p, g) }, "×"));
}

// The provider's people in a group, and pickers and changes for them.
const groupPeople = (g) => idp ? idp.people.filter((pp) => pp.groups.includes(g)) : [];

function personPicker(skip) {
  const box = el("div", { class: "pick-list" });
  const rows = (idp ? idp.people : []).filter((pp) => !skip(pp)).map((pp) => el("label", {},
    el("input", { type: "checkbox", value: pp.id }), displayName(pp), el("small", {}, pp.email)));
  put(box, ...(rows.length ? rows : [el("p", { class: "hint" }, "Nobody else.")]));
  return { el: box, chosen: () => [...box.querySelectorAll("input:checked")].map((c) => idp.people.find((pp) => pp.id === c.value)) };
}

async function patchPersonGroups(pp, groups) {
  try { await call("PATCH", `/v1/admin/people/${encodeURIComponent(pp.id)}`, { groups: [...new Set(groups)] }); return true; }
  catch (e) { notice(`${displayName(pp)}: ${e.message}`); return false; }
}

async function addPeopleToGroup(g) {
  const pick = personPicker((pp) => pp.groups.includes(g));
  if (!await ask(`Add people to ${g}`, "Their devices get what the group's rules give it at their next sign-in or refresh (within minutes).", { body: pick.el, ok: "Add" })) return;
  let ok = 0;
  for (const pp of pick.chosen()) if (await patchPersonGroups(pp, [...pp.groups, g])) ok++;
  if (ok) notice(`${plural(ok, "person", "people")} added to ${g}.`, true);
  personCache.clear();
  load();
}

async function removePersonFromGroup(pp, g) {
  if (!await ask(`Remove ${displayName(pp)} from ${g}?`, "Their devices lose what the group's rules give them within minutes.", { ok: "Remove", danger: true })) return;
  if (await patchPersonGroups(pp, pp.groups.filter((x) => x !== g))) notice(`${displayName(pp)} left ${g}.`, true);
  personCache.delete(pp.id);
  load();
}

async function deleteGroup(g) {
  if (!await ask(`Delete group ${g}?`, "It is removed from the network's sign-in. Refused while a rule, device, invitation, link or person still uses it.", { ok: "Delete", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/groups/${encodeURIComponent(g)}`);
    notice(`Group ${g} deleted.`, true);
    ui.group = null;
  } catch (e) { notice(e.message); }
  load();
}

async function removeFromGroup(p, g) {
  if (await ask(`Remove ${p.hostname} from ${g}?`, "It loses what the group's rules give it.", { ok: "Remove", danger: true }))
    setGroups([p], (d) => ownGroups(d).filter((x) => x !== g), `left ${g}`);
}

async function addToGroup(g) {
  const pick = devicePicker((p) => ownGroups(p).includes(g));
  if (await ask(`Add devices to ${g}`, "They get what the group's rules give it.", { body: pick.el, ok: "Add" }))
    setGroups(pick.chosen(), (p) => [...ownGroups(p), g], `added to ${g}`);
}

$("group-new").addEventListener("click", async () => {
  const name = el("input", { class: "input", placeholder: "group name", autocomplete: "off", "aria-label": "Group name" });
  const kind = el("div", { class: "seg", role: "group", "aria-label": "Kind" });
  const devBox = el("div", { class: "stack" }), peopleBox = el("div", { class: "stack" });
  const pick = devicePicker(() => false);
  const people = idp ? personPicker(() => false) : null;
  devBox.append(el("h3", {}, "Its first devices (optional)"), pick.el);
  if (people) peopleBox.append(el("h3", {}, "Its first people (optional)"), people.el);
  let chosenKind = idp ? "people" : "devices";
  const drawKind = () => {
    put(kind, ...[["people", "People"], ["devices", "Devices"]].filter(([k]) => idp || k === "devices").map(([k, label]) =>
      el("button", { type: "button", "aria-pressed": String(k === chosenKind), onclick: () => { chosenKind = k; drawKind(); } }, label)));
    devBox.hidden = chosenKind !== "devices";
    peopleBox.hidden = chosenKind !== "people";
  };
  drawKind();
  if (!await ask("New group", "People groups hold people (their sign-in), device groups hold devices; rules can join either. Lowercase letters, digits, - _ /.",
    { body: el("div", { class: "stack" }, kind, name, devBox, peopleBox), ok: "Create" })) return;
  const plain = name.value.trim();
  if (!plain) return notice("A new group needs a name.");
  const g = chosenKind === "devices" ? DEV + plain : plain;
  if (idp) {
    try { await call("POST", "/v1/admin/groups", { name: plain, kind: chosenKind }); } catch (e) { return notice(`${plain}: ${e.message}`); }
    if (chosenKind === "people") for (const pp of people.chosen()) await patchPersonGroups(pp, [...pp.groups, g]);
  }
  ui.group = g;
  const chosen = chosenKind === "devices" ? pick.chosen() : [];
  if (chosen.length) setGroups(chosen, (p) => [...new Set([...ownGroups(p), g])], `added to ${plain}`);
  else { notice(`Group ${plain} made.`, true); load(); }
});

async function setGroups(chosen, groupsOf, done) {
  const failed = [];
  for (const p of chosen) {
    try { await call("PATCH", `/v1/admin/peers/${p.id}`, { groups: groupsOf(p) }); } catch (e) { failed.push(`${p.hostname}: ${e.message}`); }
  }
  if (failed.length) notice(failed.join("; "));
  else if (chosen.length) notice(`${chosen.map((p) => p.hostname).join(", ")} ${done}.`, true);
  load();
}

// --- rules (policies) -----------------------------------------------------------------------------
let policyDestination = null; // set by "Allow…" on the Routes page
let policySource = null; // set by "Allow from this group" on the Groups page
let policyChecks = []; // the checks chosen for a new rule

// policyNotice confirms a rule change, or, when another rule makes posture checks moot (it connects
// the same devices without them), says so and stays on screen.
function policyNotice(done, r) {
  const w = (r && r.warnings) || [];
  if (w.length) notice(`${done} Warning: ${w.join("; ")}.`);
  else notice(done, true);
}

function renderPolicies() {
  const f = $("policy-form");
  const opt = (v, label) => el("option", { value: v }, label);
  const keep = (sel, fill) => { const v = sel.value; fill(); if (v && [...sel.options].some((o) => o.value === v)) sel.value = v; };
  const deviceGroups = () => deviceGroupList().filter((g) => g !== DEV + "isolated");
  keep(f.source, () => put(f.source, opt("", "choose…"),
    el("optgroup", { label: "People" }, ...peopleGroupList().map((g) => opt(g, g))),
    el("optgroup", { label: "Whoever" }, opt("*signed-in", whoNames["*signed-in"]), opt("*nobody", whoNames["*nobody"]), opt("*", whoNames["*"]))));
  keep(f.on, () => put(f.on, opt("", "any device"), ...deviceGroups().map((g) => opt(g, gname(g)))));
  const services = (info && info.services) || [];
  keep(f.destination, () => put(f.destination, opt("", "choose…"),
    el("optgroup", { label: "Devices" }, opt("*", "every device"), ...deviceGroups().map((g) => opt(g, gname(g)))),
    routesKnown().length ? el("optgroup", { label: "Routes" }, ...routesKnown().map((r) => opt("route:" + r, r))) : null,
    services.length ? el("optgroup", { label: "Forwarded services" }, ...services.map((n) => opt(SVC + n, n))) : null));
  if (policySource) {
    if (isDev(policySource)) { f.source.value = "*"; f.on.value = policySource.startsWith(DEV) ? policySource : DEV + policySource; }
    else f.source.value = policySource;
    f.destination.focus();
    policySource = null;
  }
  if (policyDestination) {
    f.destination.value = policyDestination;
    f.source.focus();
    policyDestination = null;
  }
  ruleHint();
  $("policy-checks-btn").textContent = policyChecks.length ? `checks: ${policyChecks.join(", ")}` : "device checks…";
  put($("policy-list"), ...list(policies.map((p) => {
    const guarded = (p.posture || []).length > 0;
    // Operators neither change a rule's checks nor remove a rule that has some.
    const acts = [];
    const svc = p.destination.startsWith(SVC);
    if ((isAdmin() || !guarded) && !(svc && p.one_way)) acts.push(button(p.one_way ? "Ports" : "Make one way", () => editRules(p), "link"));
    if (isAdmin()) acts.push(button("Checks", () => editChecks(p), "link"));
    if (isAdmin() || !guarded) acts.push(button("Remove", () => disallow(p), "link danger"));
    const who = ruleWho(p), on = ruleOn(p);
    const toName = (x) => x.startsWith(SVC) ? [icon("names", 13), " ", endLabel(x)] : x.startsWith("route:") || x === "*" ? endLabel(x) : [icon("laptop", 13), " ", gname(x)];
    return el("div", { class: "rule" },
      el("div", { class: "flow" },
        el("span", { class: "from-g" }, whoNames[who] ? whoNames[who] : [icon("people", 13), " ", gname(who)]),
        el("span", { class: "on-g" }, "on ", on ? el("b", {}, icon("laptop", 12), " ", gname(on)) : el("b", {}, "any device")),
        el("span", { class: "arrow", title: p.one_way ? "opens connections; the other side answers" : "an old rule both ways: make it one way and add the reverse", role: "img", "aria-label": p.one_way ? "reaches" : "and back, both ways (an old rule)" }, icon(p.one_way ? "one" : "both", 26)),
        el("span", { class: "to-g" }, toName(p.destination)),
        el("span", { class: "ports-t" }, svc ? "its own port" : (p.ports || []).length ? p.ports.join(", ") : "all ports"),
        guarded ? badge("passing " + p.posture.join(", "), "warn") : null,
        p.one_way ? null : badge("old rule, both ways", "warn")),
      el("div", { class: "row-actions" }, acts));
  }), "No rules: devices reach nothing."));
}

// ruleHint says in words what the rule being made allows, and keeps ports off for a service.
function ruleHint() {
  const f = $("policy-form");
  const svc = f.destination.value.startsWith(SVC);
  f.ports.disabled = svc;
  f.ports.placeholder = svc ? "its own port" : "all ports";
  if (svc) f.ports.value = "";
  const who = f.source.value, on = f.on.value, to = f.destination.value;
  if (!who || !to) { $("policy-hint").textContent = ""; return; }
  const devs = on ? `a device of ${gname(on)}` : "any device";
  const subject = who === "*" ? `Anyone or nobody signed in on ${devs}` : who === "*signed-in" ? `Anyone signed in on ${devs}` :
    who === "*nobody" ? `${devs[0].toUpperCase() + devs.slice(1)} with nobody signed in` : `People of ${who}, while signed in on ${devs},`;
  $("policy-hint").textContent = `${subject} may open connections to ${endLabel(to)}${svc ? "" : " on " + (f.ports.value.trim() || "every port")}.`;
}
["source", "on", "destination", "ports"].forEach((n) => $("policy-form")[n].addEventListener(n === "ports" ? "input" : "change", ruleHint));

function routesKnown() {
  const all = new Set(routes.map((r) => r.name));
  policies.forEach((p) => { if (p.destination.startsWith("route:")) all.add(p.destination.slice(6)); });
  return [...all];
}

// checkBoxes lists the network's posture checks with a checkbox each.
function checkBoxes(chosen) {
  const box = el("div", { class: "pick-list" }, ...(checks.length ? checks.map((c) => el("label", {},
    el("input", { type: "checkbox", value: c.name, checked: chosen.includes(c.name) }), c.name, el("small", {}, checkRequires(c).join(", ") || "a recent report")))
    : [el("p", { class: "hint" }, "No device checks yet: add one below.")]));
  return { el: box, chosen: () => [...box.querySelectorAll("input:checked")].map((i) => i.value) };
}

$("policy-checks-btn").addEventListener("click", async () => {
  const pick = checkBoxes(policyChecks);
  if (!await ask("Device checks for the new rule", "Devices it comes from reach through it only while they pass every check ticked.", { body: pick.el, ok: "Use these" })) return;
  policyChecks = pick.chosen();
  renderPolicies();
});

async function editChecks(p) {
  const pick = checkBoxes(p.posture || []);
  if (!await ask(`Checks for ${ruleText(p)}`,
    `Its devices reach ${endLabel(p.destination)} through this rule only while they pass every check ticked.`, { body: pick.el, ok: "Save" })) return;
  try {
    const r = await call("PATCH", `/v1/admin/policies/${p.id}`, { posture: pick.chosen() });
    policyNotice("Rule changed.", r);
  } catch (e) { notice("Rule: " + e.message); }
  load();
}

// portList reads a list of port rules typed in a field: "all" or nothing is every port.
// portList reads the ports typed for a rule: nothing or "all" is every port; a bare number or range
// is TCP (22, 8000-8100); otherwise tcp/22, udp/53, icmp. It throws a plain explanation otherwise.
function portList(text) {
  const l = text.split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (l.length === 1 && l[0] === "all") return [];
  return l.map((x) => {
    if (/^\d+(-\d+)?$/.test(x)) x = "tcp/" + x;
    if (!/^((tcp|udp)(\/\d+(-\d+)?)?|icmp)$/.test(x)) {
      throw new Error(`"${x}" is not a port: write a number (22), a range (8000-8100), udp/53, icmp, or leave it empty for every port`);
    }
    return x;
  });
}

async function editRules(p) {
  const ports = el("input", { class: "input mono", value: (p.ports || []).join(", "), placeholder: "all", autocomplete: "off", "aria-label": "Ports" });
  const body = el("div", { class: "stack" },
    p.one_way ? null : el("p", { class: "hint" }, `Saving makes it one way: only ${whoLabel(ruleWho(p))} opens connections. For ${endLabel(p.destination)} to open them too, add the rule the other way.`),
    el("label", { class: "field" }, el("span", {}, "Ports"), ports));
  if (!await ask(ruleText(p),
    "Ports: all, or e.g. tcp/22, tcp/443, udp/53, icmp. Enforced by the receiving device's agent (0.19 and later).", { body, ok: "Save" })) return;
  try {
    const r = await call("PUT", `/v1/admin/policies/${p.id}/rules`, { one_way: true, ports: portList(ports.value) });
    policyNotice("Rule changed.", r);
  } catch (e) { notice("Rule: " + e.message); }
  load();
}

async function disallow(p) {
  if (!await ask(`Remove ${ruleText(p)}?`, `They stop reaching ${endLabel(p.destination)} through it (unless another rule allows it).`, { ok: "Remove", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/policies/${p.id}`);
    notice("Rule removed.", true);
  } catch (e) { notice("Rule: " + e.message); }
  load();
}

$("policy-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  try {
    const posture = isAdmin() ? policyChecks : [];
    const r = await call("POST", "/v1/admin/policies", { source: f.source.value.trim(), on: f.on.value, destination: f.destination.value.trim(), posture,
      one_way: true, ports: f.ports.disabled ? [] : portList(f.ports.value) });
    policyNotice("Rule added.", r);
    f.reset();
    policyChecks = [];
    ruleHint();
  } catch (e) { notice("Rule: " + e.message); }
  load();
});

// --- device checks (posture) ----------------------------------------------------------------------
function checkRequires(c) {
  const r = [];
  if (c.disk_encryption) r.push("disk encrypted");
  if (c.firewall) r.push("firewall on");
  if (c.secure_boot) r.push("Secure Boot on");
  if (c.antimalware) r.push("anti-malware on");
  return r;
}

function renderChecks() {
  put($("check-list"), ...list(checks.map((c) => {
    const users = policies.filter((p) => (p.posture || []).includes(c.name));
    const linkUsers = links.filter((l) => (l.posture || []).includes(c.name));
    const results = peers.map((p) => (p.posture_checks || []).find((r) => r.check === c.name)).filter(Boolean);
    const required = results.filter((r) => r.required);
    const failing = peers.filter((p) => (p.posture_checks || []).some((r) => r.check === c.name && r.required && !r.passed));
    const systems = Object.entries(c.min_os || {}).sort().map(([os, v]) => `${systemNames[os] || os} ${v}`);
    const patches = Object.entries(c.max_patch_age_days || {}).sort().map(([os, d]) => `${systemNames[os] || os} patch ≤ ${d} days`);
    return el("div", { class: "rule" },
      el("div", { class: "stack" },
        el("div", { class: "flow" }, el("b", {}, c.name), [...checkRequires(c), ...systems, ...patches].map((x) => tag(x)),
          el("span", { class: "dim small" }, "report ≤ " + span(c.max_age_seconds))),
        el("div", { class: "dim small" }, users.length || linkUsers.length ? "Required by " + [...users.map(ruleText), ...linkUsers.map((l) => `link ${l.name}`)].join(", ")
          : "No rule or link requires it.",
          " · ", required.length ? `${required.length - failing.length} of ${required.length} pass` : `${results.filter((r) => r.passed).length} of ${results.length} would pass`,
          failing.length ? ` · failing: ${few(failing.map((p) => p.hostname))}` : "")),
      isAdmin() ? button("Delete", () => removeCheck(c, users, linkUsers), "link danger") : null);
  }), "No device checks."));
}

async function removeCheck(c, users, linkUsers) {
  const by = [...users.map(ruleText), ...linkUsers.map((l) => `link ${l.name}`)];
  if (by.length) return notice(`${c.name} is required by ${by.join(", ")}: take it off there first.`);
  if (!await ask(`Delete device check ${c.name}?`, "No rule or link requires it.", { ok: "Delete", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/posture/${encodeURIComponent(c.name)}`);
    notice(`Device check ${c.name} deleted.`, true);
  } catch (e) { notice(`${c.name}: ${e.message}`); }
  load();
}

$("check-new").addEventListener("click", async () => {
  const form = $("posture-template").content.firstElementChild.cloneNode(true);
  const f = (n) => form.querySelector(`[name="${n}"]`);
  if (!await ask("New device check", "", { body: form, ok: "Add check" })) return;
  if (![...form.querySelectorAll("input")].every((i) => i.checkValidity())) return notice("Device check: a field is not valid (name: lowercase letters, digits and dashes).");
  const min_os = {};
  for (const os of ["linux", "windows", "darwin", "android"]) {
    const v = f("min_" + os).value.trim();
    if (v) min_os[os] = v;
  }
  try {
    const max_patch_age_days = f("patch_android").value ? { android: Number(f("patch_android").value) } : undefined;
    const name = f("name").value.trim();
    const added = await call("POST", "/v1/admin/posture", { name, disk_encryption: f("disk_encryption").checked,
      firewall: f("firewall").checked, secure_boot: f("secure_boot").checked, antimalware: f("antimalware").checked, min_os, max_patch_age_days,
      max_age_seconds: Number(f("max_age").value) });
    if (max_patch_age_days && !added.max_patch_age_days) {
      notice(`Device check ${added.name} was added WITHOUT its security patch age: a control node is older than ento 0.30. Delete it, upgrade every control node and add it again.`);
    } else notice(`Device check ${name} added. Require it on a rule: Checks.`, true);
  } catch (e) { notice("Device check: " + e.message); }
  load();
});

// --- routes ---------------------------------------------------------------------------------------
function renderRoutes() {
  const via = $("route-via");
  const current = via.value;
  // Devices of the groups that are never gateways (--no-gateways) are not offered.
  const never = info.no_gateways || [];
  const barred = (p) => never.some((g) => (p.groups || []).includes(g) || (p.machine_groups || []).includes(g));
  put(via, ...peers.filter((p) => p.approved && !p.suspended && !barred(p)).map((p) => p.hostname).sort().map((h) => el("option", { value: h }, h)));
  $("route-never").textContent = never.length ? `Devices in ${never.join(", ")} are never gateways here.` : "";
  $("route-never").hidden = !never.length;
  if (current) via.value = current;
  put($("route-list"), ...list(routes.map((r) => {
    const users = policies.filter((p) => p.destination === "route:" + r.name);
    return el("div", { class: "item" },
      el("span", { class: "ico" }, icon("routes", 20)),
      el("div", { class: "who" }, el("b", {}, r.name),
        el("small", {}, "through ", el("span", { class: "mono" }, r.via), " · ", users.length ? "reached by " + users.map((p) => whoLabel(ruleWho(p)) + (ruleOn(p) ? " on " + gname(ruleOn(p)) : "") + ((p.ports || []).length ? ` (${p.ports.join(", ")})` : "")).join(", ") : "nobody reaches it yet"),
        (r.warnings || []).map((w) => el("small", { class: "warn-text" }, w))),
      el("div", { class: "tags" }, r.exit ? badge(r.default ? "exit, used by default" : "exit", "info") : r.networks.map((n) => tag(n, "tag mono"))),
      el("div", { class: "row-actions" }, button("Allow…", () => { policyDestination = "route:" + r.name; location.hash = "#access"; }, "btn xs"),
        isAdmin() ? button("Delete", () => removeRoute(r, users), "btn xs danger") : null));
  }), "No routes. A route lets devices reach a network behind a gateway, such as an office LAN, or use an exit to the internet."));
}

async function removeRoute(r, users) {
  if (users.length) return notice(`${r.name}: remove the rules that lead to it first (${users.map(ruleText).join(", ")}).`);
  const what = r.exit ? "using it as their exit" : `reaching ${r.networks.join(", ")} through ${r.via}`;
  if (!await ask(`Delete route ${r.name}?`, `Devices stop ${what}.`, { ok: "Delete", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/routes/${encodeURIComponent(r.name)}`);
    notice(`Route ${r.name} deleted.`, true);
  } catch (e) { notice(`${r.name}: ${e.message}`); }
  load();
}

// routeKind shows the fields of the kind of route chosen: networks, or an exit's default.
function routeKind() {
  const exit = $("route-kind").value === "exit";
  $("route-networks").hidden = exit;
  $("route-form").elements.networks.required = !exit;
  $("route-default").hidden = !exit;
  $("route-hint").textContent = exit
    ? "All internet traffic of the devices that use it goes through the gateway (ento 0.25 or later; devices on Linux and Android). Each device turns it on itself, or uses it by default. Public addresses only."
    : "The gateway (a Linux device there) forwards only what a rule allows, under its own LAN address: the office router needs no change.";
}
$("route-kind").addEventListener("change", routeKind);

$("route-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const exit = f.elements.kind.value === "exit";
  try {
    const r = await call("POST", "/v1/admin/routes", { name: f.elements.name.value.trim(), via: f.elements.via.value,
      networks: exit ? [] : f.elements.networks.value.split(",").map((s) => s.trim()).filter(Boolean),
      exit, default: exit && f.elements.default.checked });
    notice((r.warnings || []).length ? `Route ${r.name} added. ${r.warnings.join(" ")}` : `Route ${r.name} added. Let a group reach it: Allow…`, !(r.warnings || []).length);
    f.reset();
    routeKind();
  } catch (e) { notice("Route: " + e.message); }
  load();
});

// --- names (internal DNS) -------------------------------------------------------------------------
function renderNames() {
  const on = !!dns.domain;
  $("dns-sub").textContent = on
    ? `Devices resolve each other as NAME.${dns.domain}, and the names added here when they reach the address. Linux and Android devices (ento 0.26 or later).`
    : "This network has no internal DNS: its control nodes need a domain (--dns-domain, e.g. example.internal).";
  $("dns-on").hidden = !on;
  if (!on) return;
  $("dns-suffix").textContent = "." + dns.domain;
  const added = (x) => [x.created_by || "", x.created_at ? new Date(x.created_at).toLocaleDateString() : ""].filter(Boolean).join(", ");
  put($("dns-records"), ...list(dns.records.map((r) => el("div", { class: "item" },
    el("div", { class: "who" }, el("b", { class: "mono" }, `${r.name}.${dns.domain}`), el("small", {}, "added " + added(r)),
      (r.warnings || []).map((w) => el("small", { class: "warn-text" }, w))),
    el("span", { class: "mono" }, r.address),
    isAdmin() ? button("Delete", () => removeName("records", r.name, `${r.name}.${dns.domain}`), "btn xs danger") : null)), "No names added yet."));
  put($("dns-forwards"), ...list(dns.forwards.map((f) => el("div", { class: "item" },
    el("div", { class: "who" }, el("b", { class: "mono" }, f.zone), el("small", {}, "added " + added(f))),
    el("span", { class: "mono" }, f.servers.join(", ")),
    isAdmin() ? button("Delete", () => removeName("forwards", f.zone, `forwarding of ${f.zone}`), "btn xs danger") : null)), "No zones forwarded."));
  const devices = peers.filter((p) => p.approved && !p.suspended).sort((a, b) => a.hostname.localeCompare(b.hostname));
  put($("dns-devices"), ...list(devices.map((p) => el("div", { class: "item" },
    el("div", { class: "who" }, el("b", { class: "mono" }, `${p.hostname}.${dns.domain}`)), el("span", { class: "mono dim" }, p.address))),
    "No approved devices."));
}

async function removeName(kind, key, label) {
  if (!await ask(`Delete ${label}?`, "Devices stop resolving it within seconds.", { ok: "Delete", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/dns/${kind}/${encodeURIComponent(key)}`);
    notice(`Deleted ${label}.`, true);
  } catch (e) { notice(`${label}: ${e.message}`); }
  load();
}

$("dns-record-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  try {
    const r = await call("POST", "/v1/admin/dns/records", { name: f.elements.name.value.trim(), address: f.elements.address.value.trim() });
    notice(`${r.name}.${dns.domain} is ${r.address} for the devices that reach it.`, true);
    f.reset();
  } catch (e) { notice("Name: " + e.message); }
  load();
});

$("dns-forward-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  try {
    const r = await call("POST", "/v1/admin/dns/forwards", { zone: f.elements.zone.value.trim(),
      servers: f.elements.servers.value.split(",").map((s) => s.trim()).filter(Boolean) });
    notice(`Names in ${r.zone} are asked of ${r.servers.join(", ")}.`, true);
    f.reset();
  } catch (e) { notice("Zone: " + e.message); }
  load();
});

// --- linked networks ------------------------------------------------------------------------------
function renderLinks() {
  const byNetwork = new Map();
  for (const l of links) {
    const k = l.network || "none:" + l.name;
    if (!byNetwork.has(k)) byNetwork.set(k, []);
    byNetwork.get(k).push(l);
  }
  const blocks = [];
  for (const ls of byNetwork.values()) {
    blocks.push(el("div", { class: "card-head" }, el("span", { class: "dim small" }, ls[0].network
      ? ["Network with control nodes ", el("span", { class: "mono" }, (ls[0].controls || []).join(", ")), ls.length > 1 ? ` · ${ls.length} links into it` : null]
      : "Network not known yet: its token has not been imported")));
    for (const l of ls) {
      const may = peers.filter((p) => !p.authority && (p.groups || []).some((g) => (l.groups || []).includes(g)));
      const required = l.posture || [];
      // Devices that would be refused a credential now (how they do on each check, as on the Devices page).
      const failing = may.filter((p) => (p.posture_checks || []).some((r) => required.includes(r.check) && !r.passed));
      blocks.push(el("div", { class: "rule" },
        el("div", { class: "stack" },
          el("div", { class: "flow" }, el("b", {}, l.name), el("span", { class: "dim small" }, "our"), (l.groups || []).map((g) => el("span", { class: "from-g" }, g)),
            el("span", { class: "arrow" }, icon("one", 26)), el("span", { class: "dim small" }, "there"), (l.grant || []).map((g) => el("span", { class: "to-g" }, g)),
            l.has_token ? null : badge("token missing", "warn")),
          el("div", { class: "dim small", title: may.map((p) => p.hostname).join(", ") },
            may.length ? `${plural(may.length, "device")} may join: ${few(may.map((p) => p.hostname))}` : "No devices may join yet",
            ` · credentials last ${span(l.ttl_seconds)}`,
            required.length ? ` · must pass ${required.join(", ")}` : "",
            failing.length ? ` · failing now: ${few(failing.map((p) => p.hostname))}` : "")),
        isAdmin() ? el("div", { class: "row-actions" }, button("Checks", () => editLinkChecks(l), "link"), button("Delete", () => removeNamed("links", l.name, "link"), "link danger")) : null));
    }
  }
  put($("link-list"), ...(blocks.length ? blocks : [empty("No links.")]));
  put($("authority-list"), ...list(auths.map((a) => el("div", { class: "item" },
    el("span", { class: "ico" }, icon("links", 20)),
    el("div", { class: "who" }, el("b", {}, a.name), el("small", {}, `${plural(a.devices, "device")} · approvals up to ${span(a.max_ttl_seconds)}`)),
    el("div", { class: "tags" }, (a.groups || []).map((g) => tag(g)), a.suspended ? badge("suspended", "bad") : null),
    authorityActions(a))), "No authorities."));
}

// A link's checks: devices of its groups get credentials for the other network only while they pass
// them (those they have expire, within the link's lifetime or 10 minutes for signed-in devices).
async function editLinkChecks(l) {
  const pick = checkBoxes(l.posture || []);
  if (!await ask(`Checks for link ${l.name}`,
    `Devices of ${(l.groups || []).join(", ")} get credentials for this network only while they pass every check ticked, with a recent report.`,
    { body: pick.el, ok: "Save" })) return;
  try {
    await call("PATCH", `/v1/admin/links/${encodeURIComponent(l.name)}`, { posture: pick.chosen() });
    notice(`Link ${l.name} changed.`, true);
  } catch (e) { notice(`Link ${l.name}: ${e.message}`); }
  load();
}

// An authority's token is its enrollment key, reusable by every device it admits: it goes with the
// authority. Suspending stops it (and the approval of its devices) until resumed; deleting removes
// its devices too.
function authorityActions(a) {
  if (!isAdmin()) return el("div", { class: "row-actions" });
  return el("div", { class: "row-actions" },
    button(a.suspended ? "Resume" : "Suspend", () => suspendAuthority(a, !a.suspended), "btn xs"),
    button("Delete", () => removeNamed("authorities", a.name, "authority"), "btn xs danger"));
}

async function suspendAuthority(a, suspend) {
  if (suspend && !await ask(`Suspend authority ${a.name}?`,
    "It admits no device and renews no credential; the devices it admitted lose their access at once. Resuming it lets them back with their next credential.",
    { ok: "Suspend", danger: true })) return;
  try {
    await call("PATCH", `/v1/admin/authorities/${encodeURIComponent(a.name)}`, { suspended: suspend });
    notice(`Authority ${a.name} ${suspend ? "suspended" : "resumed"}.`, true);
  } catch (e) { notice(`Authority ${a.name}: ${e.message}`); }
  load();
}

async function removeNamed(kind, name, what) {
  const text = what === "authority"
    ? "Every device it admitted is removed with it, and it cannot send devices here any more."
    : "Our devices leave that network; recreating the link needs the other network's token again.";
  if (!await ask(`Delete ${what} ${name}?`, text, { ok: "Delete", danger: true })) return;
  try {
    await call("DELETE", `/v1/admin/${kind}/${encodeURIComponent(name)}`);
    notice(`${what[0].toUpperCase() + what.slice(1)} ${name} deleted.`, true);
  } catch (e) { notice(`${what} ${name}: ${e.message}`); }
  load();
}

// --- navigation -----------------------------------------------------------------------------------
function show() {
  const t = tab();
  document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== t; });
  document.querySelectorAll("#nav a").forEach((a) => a.setAttribute("aria-current", a.dataset.tab === t ? "page" : "false"));
  load(t);
}

window.addEventListener("hashchange", () => { if (!pairing) { show(); window.scrollTo(0, 0); } });
setInterval(() => {
  if (!$("dialog").open && !$("add-dialog").open && !document.hidden && info && ["overview", "people", "devices", "activity"].includes(tab())) load(undefined, true);
}, 15000);
setTokenKind("words");
routeKind();
show();

// --- activity: the network's audit (ento 0.53) ----------------------------------------------------
// Every change and refusal, newest first, as the control nodes recorded them; the Overview shows the
// latest few. Entries are only ever added.
const act = { entries: [], more: false, actions: new Set(), query: "" };
const actionNames = {
  policy_added: "Rule added", policy_deleted: "Rule removed", policy_rules: "Rule's ports changed", policy_posture: "Rule's checks changed",
  forward_connection: "Forwarded service", idp_connection: "Sign-in service", admin_api: "Administration", control_cli: "Command line",
  audit_exported: "Activity exported", enrolled: "Device joined", peer_deleted: "Device removed", peer_renamed: "Device renamed",
  token_created: "Invitation made", token_deleted: "Invitation revoked", session_opened: "Signed in", session_ended: "Signed out",
};
const actionName = (a) => actionNames[a] || (a.charAt(0).toUpperCase() + a.slice(1)).replaceAll("_", " ").replace(/^Sso\b/, "SSO").replace(/\bidp\b/, "identity provider");
const shortWhen = (iso) => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

// auditItem shows an entry; compact (the Overview) says how long ago.
function auditItem(e, compact = false) {
  const by = e.device === "-" ? `control node ${e.node}` : e.person ? `${e.device} · ${e.person}` : e.device;
  return el("div", { class: "item" },
    el("span", { class: "when", title: `${when(e.at)} · recorded by ${e.node}` }, compact ? ago(e.at) : shortWhen(e.at)),
    el("div", { class: "what" }, el("b", {}, actionName(e.action)), el("span", { class: "dim" }, " · ", by, e.from && e.from !== "-" && e.from !== "local" ? ` (${e.from})` : ""),
      e.target ? el("span", { class: "target", title: e.target }, e.target) : null),
    e.result === "denied" ? badge("refused", "bad") : e.result === "failed" ? badge("failed", "warn") : badge("done", "mute"));
}

function renderRecent(page) {
  put($("ov-activity"), ...list(page ? page.entries.map((e) => auditItem(e, true)) : [], page ? "Nothing yet." : "The activity could not be read."));
}

function activityQuery(before) {
  const f = $("act-filter");
  const q = new URLSearchParams();
  if (f.q.value.trim()) q.set("q", f.q.value.trim());
  if (f.result.value) q.set("result", f.result.value);
  if (f.kind.value) q.set("action", f.kind.value);
  $("act-export").href = "/v1/admin/audit?" + new URLSearchParams([...q, ["format", "csv"]]);
  if (before) q.set("before", String(before));
  q.set("limit", "100");
  return q.toString();
}

// loadActivity reads the first page again (a refresh keeps what was read further down and adds what
// is new on top), or the next older page.
async function loadActivity(auto = false, older = false) {
  const query = activityQuery(older ? act.entries.at(-1).id : 0);
  const filters = query.replace(/(^|&)(before|limit)=[^&]*/g, "");
  const page = await call("GET", "/v1/admin/audit?" + query, undefined, auto);
  if (older) {
    act.entries.push(...page.entries);
    act.more = page.more;
  } else if (auto && filters === act.query && act.entries.length) {
    const top = act.entries[0].id;
    act.entries.unshift(...page.entries.filter((e) => e.id > top));
  } else {
    act.entries = page.entries;
    act.more = page.more;
  }
  act.query = filters;
  page.entries.forEach((e) => act.actions.add(e.action));
  renderActivity();
}

function renderActivity() {
  const kind = $("act-filter").kind;
  const chosen = kind.value;
  put(kind, el("option", { value: "" }, "every kind"),
    ...[...act.actions, chosen].filter(Boolean).filter((a, i, all) => all.indexOf(a) === i)
      .sort((a, b) => actionName(a).localeCompare(actionName(b))).map((a) => el("option", { value: a }, actionName(a))));
  kind.value = chosen;
  put($("act-list"), ...list(act.entries.map(auditItem), act.query ? "Nothing matches." : "Nothing yet."));
  $("act-more").hidden = !act.more;
}

let actTimer = null;
$("act-filter").addEventListener("submit", (ev) => ev.preventDefault());
$("act-filter").addEventListener("input", () => {
  clearTimeout(actTimer);
  actTimer = setTimeout(() => loadActivity().catch((e) => notice("Could not load: " + e.message)), 300);
});
$("act-older").addEventListener("click", () => loadActivity(false, true).catch((e) => notice("Could not load: " + e.message)));
