const defaultApi = "http://localhost:8000";
const apiBaseInput = document.getElementById("apiBase");
const apiStatus = document.getElementById("apiStatus");
const saveApiBaseButton = document.getElementById("saveApiBase");
const scansList = document.getElementById("scansList");
const scanDetails = document.getElementById("scanDetails");
const detailHint = document.getElementById("detailHint");
const scanSearch = document.getElementById("scanSearch");
const statusFilter = document.getElementById("statusFilter");
const refreshScansButton = document.getElementById("refreshScans");

let currentJobs = [];
let activeId = null;

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

function renderSummaryBlocks(summary) {
  if (!summary || Object.keys(summary).length === 0) {
    return "<p class=\"hint\">No summary yet.</p>";
  }
  const blocks = [];
  for (const [mode, summaries] of Object.entries(summary)) {
    blocks.push(`<div class="summary-block"><h4>${mode.toUpperCase()}</h4></div>`);
    if (Array.isArray(summaries) && summaries.length) {
      summaries.forEach((item) => {
        const rows = Object.entries(item.counts || {})
          .map(([key, value]) => `<li>${key}: ${value}</li>`)
          .join("");
        blocks.push(`<div class="summary-block"><h4>${item.title}</h4><ul>${rows}</ul></div>`);
      });
    }
  }
  return blocks.join("");
}

function renderFiles(files, jobId) {
  if (!files || files.length === 0) {
    return "<p class=\"hint\">No files yet.</p>";
  }
  const base = getApiBase();
  return files
    .map((file) => {
      const name = file.name || "output";
      const path = encodeURIComponent(file.path);
      return `<a href="${base}/jobs/${jobId}/files?path=${path}">${file.mode || "run"} - ${name}</a>`;
    })
    .join("");
}

function renderScanRow(job) {
  const title = job.package_name || job.apk_path || "Job";
  const status = job.status || "running";
  const source = job.aurora_mode || (job.apk_path ? "local" : "unknown");
  const activeClass = job.id === activeId ? "active" : "";
  return `
    <div class="scan-row ${activeClass}" data-id="${job.id}">
      <div>
        <div class="scan-title">${title}</div>
        <div class="scan-meta">${job.id}</div>
        <div class="scan-meta">${source.toUpperCase()} · ${formatDate(job.created_at)}</div>
      </div>
      <span class="status ${status}">${status}</span>
    </div>
  `;
}

function renderList() {
  const query = (scanSearch.value || "").trim().toLowerCase();
  const status = statusFilter.value;
  const filtered = currentJobs.filter((job) => {
    if (status !== "all" && job.status !== status) {
      return false;
    }
    if (!query) return true;
    const haystack = `${job.package_name || ""} ${job.apk_path || ""} ${job.id}`.toLowerCase();
    return haystack.includes(query);
  });

  if (filtered.length === 0) {
    scansList.innerHTML = `<p class="hint">No scans match the filter.</p>`;
    return;
  }

  scansList.innerHTML = filtered.map(renderScanRow).join("");
}

function updateUrl(id) {
  if (!id) return;
  const url = new URL(window.location.href);
  url.searchParams.set("id", id);
  window.history.replaceState({}, "", url.toString());
}

async function loadDetails(id) {
  if (!id) {
    scanDetails.innerHTML = "";
    detailHint.textContent = "Select a scan to view details.";
    return;
  }
  const base = getApiBase();
  try {
    const resp = await fetch(`${base}/jobs/${id}`);
    if (!resp.ok) {
      throw new Error("Failed to fetch scan details");
    }
    const job = await resp.json();
    activeId = job.id;
    updateUrl(activeId);
    detailHint.textContent = "";
    const status = job.status || "running";
    const filesHtml = renderFiles(job.files || [], job.id);
    const summaryHtml = renderSummaryBlocks(job.summary);
    const logPath = job.output_root ? `${job.output_root}/runner.log` : null;
    const logLink = logPath
      ? `<a href="${base}/jobs/${job.id}/files?path=${encodeURIComponent(logPath)}">Runner Log</a>`
      : "";

    scanDetails.innerHTML = `
      <div class="details-card">
        <div class="details-title">
          <div>
            <h3>${job.package_name || job.apk_path || "Job"}</h3>
            <div class="hint">${job.id}</div>
          </div>
          <span class="status ${status}">${status}</span>
        </div>
        <div class="details-meta">
          <div><span>Created</span><strong>${formatDate(job.created_at)}</strong></div>
          <div><span>Source</span><strong>${job.aurora_mode || (job.apk_path ? "local" : "unknown")}</strong></div>
          <div><span>Auth Scan</span><strong>${job.auth_enabled ? "Yes" : "No"}</strong></div>
          <div><span>Write Tests</span><strong>${job.write_enabled ? "Yes" : "No"}</strong></div>
          <div><span>Scan Rate</span><strong>${job.scan_rate}</strong></div>
          <div><span>APK Path</span><strong>${job.apk_path || "-"}</strong></div>
        </div>
        ${job.error ? `<p class="hint" style="color: var(--danger);">Error: ${job.error}</p>` : ""}
        <div class="summary">${summaryHtml}</div>
        <div class="files">
          ${logLink}
          ${filesHtml}
        </div>
      </div>
    `;
    renderList();
  } catch (err) {
    console.error("Failed to load scan details", err);
    scanDetails.innerHTML = `<p class="hint">Failed to load scan details.</p>`;
  }
}

async function loadJobs() {
  const base = getApiBase();
  try {
    const resp = await fetch(`${base}/jobs`);
    if (!resp.ok) {
      throw new Error("Failed to fetch jobs");
    }
    currentJobs = await resp.json();
    if (!activeId && currentJobs.length) {
      const url = new URL(window.location.href);
      const requested = url.searchParams.get("id");
      activeId = requested || currentJobs[0].id;
    }
    renderList();
    if (activeId) {
      await loadDetails(activeId);
    }
  } catch (err) {
    console.error("Failed to load scans", err);
    scansList.innerHTML = `<p class="hint">Failed to load scans. Check API URL.</p>`;
  }
}

scansList.addEventListener("click", (event) => {
  const row = event.target.closest(".scan-row");
  if (!row) return;
  const id = row.dataset.id;
  if (id) {
    activeId = id;
    loadDetails(id);
  }
});

scanSearch.addEventListener("input", renderList);
statusFilter.addEventListener("change", renderList);

refreshScansButton.addEventListener("click", loadJobs);
saveApiBaseButton.addEventListener("click", () => {
  const value = apiBaseInput.value.trim();
  if (value) {
    setApiBase(value);
    checkApi();
    loadJobs();
  }
});

checkApi();
loadJobs();
setInterval(() => {
  loadJobs();
}, 15000);
