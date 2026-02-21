const defaultApi = "http://localhost:8000";
const apiBaseInput = document.getElementById("apiBase");
const apiStatus = document.getElementById("apiStatus");
const saveApiBaseButton = document.getElementById("saveApiBase");
const apksList = document.getElementById("apksList");
const apkSearch = document.getElementById("apkSearch");
const refreshApksButton = document.getElementById("refreshApks");

let currentApks = [];

function getApiBase() {
  return localStorage.getItem("apiBase") || defaultApi;
}

function setApiBase(value) {
  localStorage.setItem("apiBase", value);
}

async function checkApi() {
  const base = getApiBase();
  apiBaseInput.value = base;
  try {
    const resp = await fetch(`${base}/health`);
    if (!resp.ok) {
      throw new Error("API not reachable");
    }
    const data = await resp.json();
    apiStatus.textContent = `Online (v${data.version || "?"})`;
  } catch (err) {
    apiStatus.textContent = "Offline";
    console.error("API health check failed", err);
  }
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch (e) {
    return iso;
  }
}

function formatSize(bytes) {
  if (!bytes && bytes !== 0) return "-";
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(2)} MB`;
}

function renderRow(apk) {
  const title = apk.package_name || apk.name;
  const source = apk.aurora_mode ? apk.aurora_mode.toUpperCase() : "LOCAL";
  const viewLink = apk.job_id ? `/scans/detail.html?id=${apk.job_id}` : null;
  return `
    <div class="apk-row">
      <div class="apk-main">
        <div class="scan-title">${title}</div>
        <div class="scan-meta">${apk.name}</div>
        <div class="scan-meta">${source} · ${formatSize(apk.size)} · ${formatDate(apk.modified_at)}</div>
      </div>
      <div class="scan-actions">
        ${viewLink ? `<a class="btn-link" href="${viewLink}">View Scan</a>` : ""}
      </div>
    </div>
  `;
}

function renderList() {
  const query = (apkSearch.value || "").trim().toLowerCase();
  const filtered = currentApks.filter((apk) => {
    if (!query) return true;
    const haystack = `${apk.package_name || ""} ${apk.name || ""}`.toLowerCase();
    return haystack.includes(query);
  });

  if (filtered.length === 0) {
    apksList.innerHTML = `<p class="hint">No APKs match the filter.</p>`;
    return;
  }

  apksList.innerHTML = filtered.map(renderRow).join("");
}

async function loadApks() {
  const base = getApiBase();
  try {
    const resp = await fetch(`${base}/apks`);
    if (!resp.ok) {
      throw new Error("Failed to fetch apks");
    }
    currentApks = await resp.json();
    renderList();
  } catch (err) {
    console.error("Failed to load APKs", err);
    apksList.innerHTML = `<p class="hint">Failed to load APKs. Check API URL.</p>`;
  }
}

apkSearch.addEventListener("input", renderList);
refreshApksButton.addEventListener("click", loadApks);
saveApiBaseButton.addEventListener("click", () => {
  const value = apiBaseInput.value.trim();
  if (value) {
    setApiBase(value);
    checkApi();
    loadApks();
  }
});

checkApi();
loadApks();
setInterval(() => {
  loadApks();
}, 15000);
