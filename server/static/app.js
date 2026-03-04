const API_BASE = "/api";
const $ = (id) => document.getElementById(id);

/* -------------------------
   Session (JWT + PKCS12 pass)
-------------------------- */
let sessionToken = null;
let currentUser = null;
let currentPass = null;

function newNonce() {
  return crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + "-" + Math.random();
}

function authHeaders(extra = {}) {
  const h = { ...extra, "X-Request-Id": newNonce() }; // replay protection
  if (sessionToken) h["Authorization"] = `Bearer ${sessionToken}`;
  return h;
}

/* -------------------------
   Small UI Helpers
-------------------------- */
function safeText(el, txt, color = "") {
  if (!el) return;
  el.innerText = txt || "";
  if (color) el.style.color = color;
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[c]));
}

function escapeAttr(s) {
  return (s || "").replace(/'/g, "\\'");
}

/* -------------------------
   Navigation / Layout
-------------------------- */
function hideAll() {
  const landing = $("landingSection");
  if (landing) landing.style.display = "none";
  $("authSection")?.classList.add("hidden");
  $("dashboardSection")?.classList.add("hidden");
}

function showLanding() {
  hideAll();
  const landing = $("landingSection");
  if (landing) landing.style.display = "flex";
}

function showAuth() {
  hideAll();
  $("authSection")?.classList.remove("hidden");
}

function showDashboard() {
  hideAll();
  $("dashboardSection")?.classList.remove("hidden");
  $("logoutBtn")?.classList.remove("hidden");
  loadFiles();
}

function switchAuthTab(mode) {
  $("loginForm")?.classList.toggle("hidden", mode !== "login");
  $("registerForm")?.classList.toggle("hidden", mode !== "register");
  $("tabLogin")?.classList.toggle("active", mode === "login");
  $("tabRegister")?.classList.toggle("active", mode === "register");
}

function switchMainTab(mode) {
  $("vaultView")?.classList.toggle("hidden", mode !== "vault");
  $("signView")?.classList.toggle("hidden", mode !== "sign");
  $("btnVault")?.classList.toggle("active", mode === "vault");
  $("btnSign")?.classList.toggle("active", mode === "sign");
}

/* -------------------------
   Auth Guards
-------------------------- */
function requireLogin() {
  // Token required for protected endpoints
  if (!sessionToken || !currentUser || !currentPass) {
    alert("Login first.");
    return false;
  }
  return true;
}

function logout() {
  currentUser = null;
  currentPass = null;
  sessionToken = null;

  if ($("userDisplay")) $("userDisplay").innerText = "";
  if ($("fileList")) $("fileList").innerHTML = "";
  if ($("verifyResult")) $("verifyResult").style.display = "none";
  if ($("sigOutput")) $("sigOutput").value = "";

  ["loginUser", "loginPass", "regUser", "regPass", "verifySig"].forEach(id => {
    if ($(id)) $(id).value = "";
  });

  $("logoutBtn")?.classList.add("hidden");
  showLanding();
}

/* -------------------------
   Network Helpers
-------------------------- */
async function postJson(path, obj) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(obj || {})
  });
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

async function postForm(path, formData) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: authHeaders(), // includes token + nonce
    body: formData
  });

  const ct = (res.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("application/json")) {
    const data = await res.json().catch(() => ({}));
    return { res, data };
  }
  return { res, data: null };
}

/* -------------------------
   Register (PKI Identity)
-------------------------- */
async function register() {
  const user = $("regUser")?.value?.trim();
  const pass = $("regPass")?.value || "";
  const status = $("regStatus");

  if (!user || !pass) {
    safeText(status, "❌ user_id/email and password required", "#dc2626");
    return;
  }

  safeText(status, "Generating keys (PKI)...", "#0f172a");

  const { res, data } = await postJson("/register", { user_id: user, password: pass });

  if (res.ok && data.ok) {
    safeText(status, "✅ Success! Login now.", "#16a34a");
    setTimeout(() => switchAuthTab("login"), 1200);
  } else {
    safeText(status, `❌ ${data.error || "Registration failed"}`, "#dc2626");
  }
}

/* -------------------------
   Login (JWT + PKCS12 unlock)
-------------------------- */
async function login() {
  const u = $("loginUser")?.value?.trim();
  const p = $("loginPass")?.value || "";

  if (!u || !p) {
    alert("Enter email/user_id and password");
    return;
  }

  const statusEl = $("loginStatus");
  safeText(statusEl, "Checking credentials...", "#0f172a");

  try {
    // login route returns { ok:true, token:"..." }
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ user_id: u, password: p })
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok && data.ok && data.token) {
      sessionToken = data.token;
      currentUser = u;
      currentPass = p;

      if ($("userDisplay")) $("userDisplay").innerText = `User: ${currentUser}`;
      safeText(statusEl, "✅ Login successful", "#16a34a");

      showDashboard();
      await loadFiles();
      return;
    }

    const msg = data.error || "Login failed";
    safeText(statusEl, `❌ ${msg}`, "#dc2626");
    if ($("loginPass")) $("loginPass").value = "";
  } catch (err) {
    console.error(err);
    safeText(statusEl, "❌ Network/server error during login.", "#dc2626");
  }
}

/* -------------------------
   Vault: Upload / List / Decrypt / Delete
-------------------------- */
async function uploadFile() {
  if (!requireLogin()) return;

  const file = $("fileInput")?.files?.[0];
  const status = $("uploadStatus");
  if (!file) return;

  safeText(status, "Encrypting and storing...", "#0f172a");

  const fd = new FormData();
  fd.append("file", file);
  fd.append("password", currentPass); // token supplies user, password unlocks PKCS12

  const { res, data } = await postForm("/upload", fd);

  if (res.ok && data?.ok) {
    safeText(status, `✅ Encrypted & Stored: ${data.filename}`, "#16a34a");
    $("fileInput").value = "";
    await loadFiles();
  } else {
    safeText(status, `❌ Failed: ${data?.error || "Upload error"}`, "#dc2626");
  }
}

async function loadFiles() {
  if (!requireLogin()) return;

  const list = $("fileList");
  if (!list) return;

  list.innerHTML = `<div style="padding: 2rem; text-align: center; color: #cbd5e1;">Loading secure files...</div>`;

  const { res, data } = await postJson("/files", {}); // token supplies user

  if (!res.ok || !data.ok) {
    list.innerHTML = `<div style="padding: 2rem; text-align: center; color: #dc2626; font-weight: 700;">Failed to load files</div>`;
    return;
  }

  const files = data.files || [];
  if (files.length === 0) {
    list.innerHTML = `<div style="padding:2rem; text-align:center; color:#94a3b8">Empty Vault</div>`;
    return;
  }

  list.innerHTML = "";
  files.forEach((obj) => {
    const fname = obj.filename || "unknown";
    const fileId = obj.file_id || "";

    const row = document.createElement("div");
    row.className = "file-item";
    row.innerHTML = `
      <div style="min-width:0;">
        <div style="display:flex; align-items:center; gap:8px; min-width:0;">
          <span class="file-icon">🔒</span>
          <b style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis; display:block; max-width:520px;">
            ${escapeHtml(fname)}
          </b>
        </div>
        <div style="font-size:0.75rem;color:#94a3b8;margin-top:4px;font-family:monospace;">
          id: ${escapeHtml(fileId)}
        </div>
      </div>

      <div style="display:flex; gap:10px; align-items:center;">
        <button
          style="cursor:pointer; color:#2563eb; background:none; border:none; font-weight:bold;"
          onclick="decryptDownload('${escapeAttr(fileId)}','${escapeAttr(fname)}')"
        >Decrypt ⬇</button>

        <button
          style="cursor:pointer; color:#dc2626; background:none; border:none; font-weight:bold;"
          onclick="deleteVaultFile('${escapeAttr(fileId)}','${escapeAttr(fname)}')"
        >Delete</button>
      </div>
    `;
    list.appendChild(row);
  });
}

async function decryptDownload(fileId, fname) {
  if (!requireLogin()) return;
  if (!fileId) return alert("Missing file id.");

  const status = $("uploadStatus");
  safeText(status, "Decrypting...", "#0f172a");

  const fd = new FormData();
  fd.append("password", currentPass);

  const res = await fetch(`${API_BASE}/decrypt/${encodeURIComponent(fileId)}`, {
    method: "POST",
    headers: authHeaders(),
    body: fd
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    safeText(status, `❌ Decryption Failed: ${err.error || "Server error"}`, "#dc2626");
    return;
  }

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = fname || "decrypted_file";
  document.body.appendChild(a);
  a.click();
  a.remove();

  window.URL.revokeObjectURL(url);
  safeText(status, `✅ Decrypted & Downloaded: ${fname}`, "#16a34a");
}

async function deleteVaultFile(fileId, fname) {
  if (!requireLogin()) return;
  if (!fileId) return alert("Missing file id.");

  const sure = confirm(`Delete "${fname}"?\nThis cannot be undone.`);
  if (!sure) return;

  const status = $("uploadStatus");
  safeText(status, "Deleting...", "#0f172a");

  const fd = new FormData();
  fd.append("password", currentPass);

  const { res, data } = await postForm(`/delete/${encodeURIComponent(fileId)}`, fd);

  if (res.ok && data?.ok) {
    safeText(status, `✅ Deleted: ${fname}`, "#16a34a");
    await loadFiles();
  } else {
    safeText(status, `❌ Delete failed: ${data?.error || "Server error"}`, "#dc2626");
  }
}

/* -------------------------
   Digital Signatures UI
-------------------------- */
async function signFile() {
  if (!requireLogin()) return;

  const file = $("signInput")?.files?.[0];
  if (!file) return alert("Select file first");

  const fd = new FormData();
  fd.append("file", file);
  fd.append("password", currentPass);

  const { res, data } = await postForm("/sign", fd);

  if (res.ok && data?.ok) {
    if ($("sigOutput")) $("sigOutput").value = data.signature_hex || "";
  } else {
    alert("Error: " + (data?.error || "sign failed"));
  }
}

async function verifyFile() {
  if (!requireLogin()) return;

  const file = $("verifyInput")?.files?.[0];
  const sig = $("verifySig")?.value?.trim() || "";
  const box = $("verifyResult");

  if (!file || !sig) return alert("Need file and signature");

  const fd = new FormData();
  fd.append("file", file);
  fd.append("signature", sig);
  fd.append("password", currentPass);

  const { res, data } = await postForm("/verify", fd);

  if (!box) return;

  box.style.display = "block";

  if (res.ok && data?.ok && data.valid === true) {
    box.className = "verify-box success";
    box.innerHTML = "✅ <b>VALID SIGNATURE</b><br>The file is authentic and has not been changed.";
  } else {
    box.className = "verify-box error";
    box.innerHTML = "❌ <b>INVALID / TAMPERED</b><br>Danger! The file or signature does not match.";
  }
}

/* -------------------------
   Expose to HTML
-------------------------- */
window.showLanding = showLanding;
window.showAuth = showAuth;
window.switchAuthTab = switchAuthTab;
window.switchMainTab = switchMainTab;

window.login = login;
window.logout = logout;
window.register = register;

window.uploadFile = uploadFile;
window.loadFiles = loadFiles;
window.decryptDownload = decryptDownload;
window.deleteVaultFile = deleteVaultFile;

window.signFile = signFile;
window.verifyFile = verifyFile;

/* Init */
document.addEventListener("DOMContentLoaded", () => {
  showLanding();
});
