// The pages of a network's sign-in (ento id): nothing loaded from elsewhere, no inline script.
"use strict";

const $ = (id) => document.getElementById(id);
const body = document.body.dataset;

function show(id, on = true) { $(id).hidden = !on; }

function error(msg) {
  show("busy", false);
  $("error").textContent = msg || "";
  show("error", !!msg);
}

function notice(msg) {
  $("notice").textContent = msg || "";
  show("notice", !!msg);
}

function done(title, text) {
  for (const s of document.querySelectorAll("section")) s.hidden = true;
  show("signin", false);
  $("done-title").textContent = title;
  $("done-text").textContent = text;
  show("done");
  error("");
}

// base64url <-> bytes
function b64(buf) {
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function call(path, data) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data || {}),
    credentials: "same-origin",
  });
  let out = {};
  try { out = await r.json(); } catch (_) { /* no body */ }
  if (!r.ok) throw new Error(out.error || "Something went wrong (" + r.status + ").");
  return out;
}

function requestOptions(o) {
  const pk = { ...o, challenge: unb64(o.challenge) };
  if (o.allowCredentials) pk.allowCredentials = o.allowCredentials.map((c) => ({ ...c, id: unb64(c.id) }));
  return pk;
}

function creationOptions(o) {
  const pk = { ...o, challenge: unb64(o.challenge), user: { ...o.user, id: unb64(o.user.id) } };
  if (o.excludeCredentials) pk.excludeCredentials = o.excludeCredentials.map((c) => ({ ...c, id: unb64(c.id) }));
  return pk;
}

function credentialJSON(c) {
  const r = c.response;
  const out = { id: c.id, rawId: b64(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {} };
  if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
  if (r.attestationObject) {
    out.response = { clientDataJSON: b64(r.clientDataJSON), attestationObject: b64(r.attestationObject) };
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    out.response = { clientDataJSON: b64(r.clientDataJSON), authenticatorData: b64(r.authenticatorData), signature: b64(r.signature) };
    if (r.userHandle) out.response.userHandle = b64(r.userHandle);
  }
  return out;
}

function passkeyError(e) {
  if (e && (e.name === "NotAllowedError" || e.name === "AbortError")) return "The passkey was not used. Try again when you are ready.";
  if (e && e.name === "InvalidStateError") return "This passkey is registered here already.";
  return (e && e.message) || "Something went wrong.";
}

function noPasskeys() {
  if (window.PublicKeyCredential) return false;
  error("This browser cannot use passkeys. Use your password, or a current browser.");
  return true;
}

async function busy(fn) {
  error("");
  show("busy");
  try { return await fn(); } finally { show("busy", false); }
}

// usePasskey runs a passkey sign-in started at path with data, and returns the provider's answer.
async function usePasskey(path, data) {
  const start = await call(path, data);
  const cred = await navigator.credentials.get({ publicKey: requestOptions(start.publicKey) });
  return call("/passkey/finish", { ceremony: start.ceremony, credential: credentialJSON(cred) });
}

// signIn shows the sign-in for goal and calls then with the provider's answer once signed in.
function signIn(goal, then) {
  show("signin");
  let step = null;
  const finish = async (fn) => {
    try { await then(await busy(fn)); }
    catch (e) { error(passkeyError(e)); }
  };
  $("passkey-go").onclick = () => { if (!noPasskeys()) finish(() => usePasskey("/passkey/begin", goal)); };
  $("password-show").onclick = (ev) => {
    ev.preventDefault();
    show("signin-start", false); show("password-form"); $("email").focus();
  };
  $("passkey-show").onclick = (ev) => {
    ev.preventDefault();
    show("password-form", false); show("signin-start");
  };
  $("password-form").onsubmit = async (ev) => {
    ev.preventDefault();
    try {
      const out = await busy(() => call("/password", { ...goal, email: $("email").value, password: $("password").value }));
      step = out.step;
      $("password").value = "";
      show("password-form", false);
      if (out.next.includes("passkey")) {
        show("second-passkey");
        show("to-code-p", out.next.includes("totp"));
      } else {
        show("second-code"); $("code").focus();
      }
    } catch (e) { error(e.message); }
  };
  $("second-passkey-go").onclick = () => { if (!noPasskeys()) finish(() => usePasskey("/password/passkey", { step })); };
  $("to-code").onclick = (ev) => {
    ev.preventDefault();
    show("second-passkey", false); show("second-code"); $("code").focus();
  };
  $("second-code").onsubmit = (ev) => {
    ev.preventDefault();
    finish(() => call("/password/totp", { step, code: $("code").value }));
  };
}

function authorize() {
  show("authorize");
  signIn({ goal: "authorize", request: body.request }, (out) => location.assign(out.redirect));
}

function deviceAnswered(out) {
  if (out.done === "declined") {
    done("Declined", "The device was not signed in. You can close this tab.");
    return;
  }
  done("Signed in", "Your device is signed in" + (out.person ? " as " + out.person : "") + ". You can close this tab.");
  setTimeout(() => window.close(), 1500);
}

function deviceSignedIn(code) {
  return (out) => {
    if (!out.confirm) { deviceAnswered(out); return; }
    show("signin", false);
    show("device-linked", false);
    $("device-person").textContent = out.person;
    $("device-confirm-code").textContent = code;
    show("device-confirm");
    const answer = async (accept) => {
      try { deviceAnswered(await call("/device/answer", { confirm: out.confirm, accept })); }
      catch (e) { error(e.message); }
    };
    $("device-accept").addEventListener("click", () => answer(true), { once: true });
    $("device-decline").addEventListener("click", () => answer(false), { once: true });
  };
}

function device() {
  show("device");
  const fromLink = new URLSearchParams(location.search).get("user_code");
  if (fromLink) {
    // The code came in a link: shown, and asked about after the sign-in.
    history.replaceState(null, "", location.pathname);
    const code = fromLink.toUpperCase();
    $("device-linked-code").textContent = code;
    show("device-linked");
    signIn({ goal: "device", user_code: code, from_link: true }, deviceSignedIn(code));
    return;
  }
  show("device-typed");
  $("device-code").focus();
  $("device-form").onsubmit = (ev) => {
    ev.preventDefault();
    const code = $("device-code").value;
    show("device-typed", false);
    signIn({ goal: "device", user_code: code, from_link: false }, deviceSignedIn(code));
  };
}

// here signs the person in on the device the browser runs on.
function here() {
  show("here");
  const then = new URLSearchParams(location.search).get("then") || "";
  signIn({ goal: "here", then }, (out) => {
    if (out.next) { location.assign(out.next); return; }
    done("Signed in", out.device + " is signed in as " + out.person + ". You can close this tab.");
    setTimeout(() => window.close(), 1500);
  });
}

// --- the account page ------------------------------------------------------------------------------

async function accountLoad() {
  const r = await fetch("/account/state", { credentials: "same-origin" });
  if (r.status === 401) {
    show("account", false);
    show("account-signin");
    signIn({ goal: "account" }, () => location.reload());
    return;
  }
  const st = await r.json();
  show("account-signin", false);
  show("signin", false);
  show("account");
  $("acct-name").textContent = st.name;
  $("acct-email").textContent = st.email;
  const list = $("acct-passkeys");
  list.replaceChildren();
  for (const k of st.passkeys) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = k.name + (k.last_used ? " · last used " + k.last_used.slice(0, 10) : " · not used yet");
    const rm = document.createElement("a");
    rm.href = "#";
    rm.textContent = "Remove";
    rm.onclick = (ev) => { ev.preventDefault(); accountDo("/account/passkey/delete", { name: k.name }, "Passkey removed."); };
    li.append(label, rm);
    list.append(li);
  }
  if (!st.passkeys.length) list.append(Object.assign(document.createElement("li"), { textContent: "None." }));
  $("acct-password-state").textContent = st.password ? "You have a password." : "You have no password.";
  $("acct-password-go").textContent = st.password ? "Change password" : "Set password";
  show("acct-password-remove-p", st.password);
  $("acct-totp-state").textContent = st.totp ? "An app gives your codes." : "No app is set up.";
  $("acct-totp-add").textContent = st.totp ? "Replace the app" : "Set up an app";
  show("acct-totp-remove-p", st.totp);
  const names = { "passkey": "a passkey", "password+passkey": "your password and a passkey", "password+totp": "your password and an app's code" };
  $("acct-allowed").textContent = "You may sign in with " + st.allowed.map((m) => names[m] || m).join(", or ") + ".";
}

async function accountDo(path, data, msg) {
  try {
    await busy(() => call(path, data));
    notice(msg);
    await accountLoad();
  } catch (e) { error(e.message); }
}

function account() {
  $("acct-passkey-add").onclick = async () => {
    if (noPasskeys()) return;
    try {
      await busy(async () => {
        const start = await call("/account/passkey/begin");
        const cred = await navigator.credentials.create({ publicKey: creationOptions(start.publicKey) });
        await call("/account/passkey/finish", { ceremony: start.ceremony, credential: credentialJSON(cred) });
      });
      notice("Passkey added.");
      await accountLoad();
    } catch (e) { error(passkeyError(e)); }
  };
  $("acct-password-form").onsubmit = (ev) => {
    ev.preventDefault();
    const pw = $("acct-password").value;
    $("acct-password").value = "";
    accountDo("/account/password", { password: pw }, "Password saved.");
  };
  $("acct-password-remove").onclick = (ev) => { ev.preventDefault(); accountDo("/account/password", { remove: true }, "Password removed."); };
  let app = null;
  $("acct-totp-add").onclick = async () => {
    try {
      const out = await busy(() => call("/account/totp/begin"));
      app = out.app;
      $("acct-totp-qr").src = out.offer.qr;
      $("acct-totp-key").textContent = out.offer.secret;
      show("acct-totp-new");
      $("acct-totp-code").focus();
    } catch (e) { error(e.message); }
  };
  $("acct-totp-form").onsubmit = async (ev) => {
    ev.preventDefault();
    await accountDo("/account/totp/finish", { app, code: $("acct-totp-code").value }, "The app is set up.");
    $("acct-totp-code").value = "";
    if ($("error").hidden) show("acct-totp-new", false);
  };
  $("acct-totp-remove").onclick = (ev) => { ev.preventDefault(); accountDo("/account/totp/delete", {}, "The app is removed."); };
  $("acct-signout").onclick = async (ev) => {
    ev.preventDefault();
    try { await call("/account/signout"); } catch (_) { /* gone anyway */ }
    location.reload();
  };
  accountLoad().catch((e) => error(e.message));
}

// --- setup links -----------------------------------------------------------------------------------

async function setup() {
  show("setup");
  const secret = location.hash.slice(1);
  // The link's secret stays out of the history and of anything the page loads.
  history.replaceState(null, "", location.pathname);
  if (!secret) { error("This link is incomplete. Open the whole link you were given."); return; }
  const finished = (out) => {
    if (out.next) { location.assign(out.next); return; }
    if (out.done === "device") {
      done("Signed in", "Your account is ready, and " + (out.device || "your device") + " is signed in as " + out.person + ". You can close this tab.");
      return;
    }
    done("Your account is ready", "You sign in to " + body.title + " with it from now on. You can close this tab.");
  };
  const next = async () => {
    let st;
    try { st = await busy(() => call("/setup/begin", { secret })); }
    catch (e) { error(e.message); return; }
    $("setup-email").textContent = st.email;
    show("setup-for");
    for (const id of ["setup-password-form", "setup-passkey", "setup-totp"]) show(id, false);
    if (st.step === "password") {
      show("setup-password-form");
      $("setup-password").focus();
      $("setup-password-form").onsubmit = async (ev) => {
        ev.preventDefault();
        try {
          await busy(() => call("/setup/password", { secret, password: $("setup-password").value }));
          $("setup-password").value = "";
          await next();
        } catch (e) { error(e.message); }
      };
    } else if (st.step === "passkey") {
      if (noPasskeys()) return;
      show("setup-passkey");
      $("setup-go").onclick = async () => {
        try {
          const out = await busy(async () => {
            const cred = await navigator.credentials.create({ publicKey: creationOptions(st.publicKey) });
            return call("/setup/finish", { ceremony: st.ceremony, credential: credentialJSON(cred) });
          });
          finished(out);
        } catch (e) {
          error(passkeyError(e));
          await next(); // a ceremony is used once: start another for the next try
        }
      };
    } else if (st.step === "totp") {
      show("setup-totp");
      $("setup-totp-qr").src = st.offer.qr;
      $("setup-totp-key").textContent = st.offer.secret;
      $("setup-totp-form").onsubmit = async (ev) => {
        ev.preventDefault();
        try { finished(await busy(() => call("/setup/totp", { secret, app: st.app, code: $("setup-totp-code").value }))); }
        catch (e) { error(e.message); }
      };
    }
  };
  await next();
}

({ authorize, device, here, setup, account, home: () => show("home"), error: () => {} })[body.mode]?.();
