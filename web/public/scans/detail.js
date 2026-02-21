const defaultApi = "http://localhost:8000";
const apiBaseInput = document.getElementById("apiBase");
const apiStatus = document.getElementById("apiStatus");
const saveApiBaseButton = document.getElementById("saveApiBase");
const scanDetails = document.getElementById("scanDetails");
const detailHint = document.getElementById("detailHint");
const scanLoadProgress = document.getElementById("scanLoadProgress");
const scanLoadProgressLabel = document.getElementById("scanLoadProgressLabel");
const deleteScanButton = document.getElementById("deleteScan");
const stopScanButton = document.getElementById("stopScan");
const logCache = new Map();
const logFetches = new Map();
const logOpenState = new Map();
const fileGroupOpenState = new Map();
const fileSearchTerms = new Map();

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

function isPackageName(value) {
  if (!value) return false;
  return /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(String(value));
}

function getScanSource(job) {
  if (job.scan_source) return job.scan_source;
  if (job.package_name) return "aurora";
  if (job.apk_path) return "local";
  if (job.output_root) return "project";
  return "unknown";
}

function getEffectiveStatus(job) {
  const baseStatus = job.status || "running";
  if (["failed", "completed", "stopped"].includes(baseStatus)) {
    return baseStatus;
  }
  return job.progress_status || baseStatus;
}

function formatSourceLabel(source) {
  const map = {
    aurora: "Searched",
    aurora_random: "Automated Pool",
    search: "Keyword Search",
    local: "Local",
    project: "Project",
    apk_dir: "APK Directory",
    device: "ADB Device",
    unknown: "Unknown",
  };
  return map[source] || String(source || "Unknown");
}

function formatSize(bytes) {
  if (!bytes && bytes !== 0) return "-";
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(2)} MB`;
}

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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

function renderApkActions(job, apk) {
  const canRestore = Boolean(job.package_name);
  const hint = apk
    ? "APK is available for download."
    : canRestore
      ? "APK was removed after scan. Re-download to keep it."
      : "Re-download is only available for Aurora downloads.";
  return `
    <div class="detail-actions">
      <button class="secondary" id="apkRestore" ${canRestore ? "" : "disabled"}>
        Download files again
      </button>
      <div class="hint" id="apkRestoreHint">${escapeHtml(hint)}</div>
    </div>
  `;
}

function resolveDownloadUrl(base, url) {
  if (!url) return "";
  if (url.startsWith("http://") || url.startsWith("https://")) {
    return url;
  }
  return `${base}${url.startsWith("/") ? "" : "/"}${url}`;
}

function wireApkRestore(job, base) {
  const button = scanDetails.querySelector("#apkRestore");
  if (!button) return;
  const hint = scanDetails.querySelector("#apkRestoreHint");
  if (button.hasAttribute("disabled")) return;

  button.addEventListener("click", async () => {
    const originalLabel = button.textContent;
    button.disabled = true;
    button.textContent = "Preparing...";
    if (hint) hint.textContent = "Preparing APK download...";
    try {
      const resp = await fetch(`${base}/jobs/${job.id}/apk/restore`, {
        method: "POST",
      });
      if (!resp.ok) {
        let detail = "Failed to restore APK.";
        try {
          const data = await resp.json();
          if (data && data.detail) detail = data.detail;
        } catch (e) {
          // ignore json parse failure
        }
        throw new Error(detail);
      }
      const data = await resp.json();
      const downloadUrl = resolveDownloadUrl(base, data.download_url);
      if (hint) hint.textContent = "APK ready. It will be kept after scan.";
      if (downloadUrl) {
        window.location.href = downloadUrl;
      }
    } catch (err) {
      console.error("Failed to restore APK", err);
      if (hint) hint.textContent = err.message || "Failed to restore APK.";
      alert(err.message || "Failed to restore APK.");
    } finally {
      button.disabled = false;
      button.textContent = originalLabel;
    }
  });
}

function escapeAttr(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function wireDeleteScan(job, base) {
  if (!deleteScanButton) return;
  const status = getEffectiveStatus(job);
  deleteScanButton.disabled = status === "running";
  deleteScanButton.addEventListener("click", async () => {
    const automated = getScanSource(job) === "aurora_random";
    const label = job.package_name ? ` ${job.package_name}` : "";
    const message = automated
      ? `Delete automated scan job${label}? This removes all results from this automated run.`
      : `Delete scan${label}? This removes all results.`;
    if (!confirm(message)) return;
    deleteScanButton.disabled = true;
    try {
      const resp = await fetch(`${base}/jobs/${job.id}`, { method: "DELETE" });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || "Failed to delete scan.");
      }
      window.location.href = "/scans/";
    } catch (err) {
      alert(err.message || "Failed to delete scan.");
      deleteScanButton.disabled = false;
    }
  });
}

function wireStopScan(job, base) {
  if (!stopScanButton) return;
  const status = getEffectiveStatus(job);
  stopScanButton.disabled = status !== "running";
  stopScanButton.addEventListener("click", async () => {
    if (!confirm("Stop this scan?")) return;
    stopScanButton.disabled = true;
    try {
      const resp = await fetch(`${base}/jobs/${job.id}/stop`, { method: "POST" });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || "Failed to stop scan.");
      }
      await loadScan();
    } catch (err) {
      alert(err.message || "Failed to stop scan.");
      stopScanButton.disabled = false;
    }
  });
}

async function hydrateSecretMatches(job, base) {
  const nodes = Array.from(scanDetails.querySelectorAll(".secret-match[data-match-path]"));
  if (!nodes.length) return;
  const cache = new Map();
  for (const node of nodes) {
    const path = node.dataset.matchPath;
    const line = node.dataset.matchLine;
    const detector = node.dataset.matchDetector;
    if (!path || !line) continue;
    const key = `${path}::${line}::${detector || ""}`;
    let promise = cache.get(key);
    if (!promise) {
      const url = `${base}/jobs/${job.id}/line?path=${encodeURIComponent(path)}&line=${encodeURIComponent(
        line
      )}${detector ? `&detector=${encodeURIComponent(detector)}` : ""}`;
      promise = fetch(url)
        .then((resp) => {
          if (!resp.ok) throw new Error("Failed to load match line");
          return resp.json();
        })
        .then((data) => data.match || data.line || "")
        .catch(() => "");
      cache.set(key, promise);
    }
    const text = await promise;
    if (text) {
      node.textContent = text;
    }
  }
}

function formatProgressStage(stage, mode) {
  if (!stage) return "";
  const map = {
    mode_started: "Starting scan",
    extracting_targets: "Extracting targets",
    targets_extracted: "Targets extracted",
    scanning_firebase: "Scanning Firebase services",
    firebase_scan_completed: "Firebase scan completed",
    scanning_secrets: "Scanning secrets",
    secrets_scan_completed: "Secrets scan completed",
    completed: "Scan completed",
    failed: "Scan failed",
  };
  const label = map[stage] || stage.replace(/_/g, " ");
  if (mode) {
    return `${label} (${mode})`;
  }
  return label;
}

function renderStatusProgress(statusRaw, progress, stage, mode) {
  const status = (statusRaw || "running").toLowerCase();
  const labelParts = [];
  const stageLabel = formatProgressStage(stage, mode);
  if (status === "completed") {
    labelParts.push("Scan completed");
  } else if (status === "failed") {
    labelParts.push("Scan failed");
  } else if (status === "stopped") {
    labelParts.push("Scan stopped");
  } else {
    labelParts.push("Scan running");
  }
  if (typeof progress === "number" && !Number.isNaN(progress)) {
    labelParts.push(`${Math.min(100, Math.max(0, Math.round(progress)))}%`);
  }
  if (stageLabel) {
    labelParts.push(stageLabel);
  }
  const label = labelParts.join(" · ");

  if (status === "completed") {
    return `
      <div class="progress-row status-progress">
        <div class="progress-label">${label}</div>
        <div class="progress-bar is-complete" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="100">
          <div class="progress-fill" style="width: 100%"></div>
        </div>
      </div>
    `;
  }
  if (status === "failed") {
    return `
      <div class="progress-row status-progress">
        <div class="progress-label">${label}</div>
        <div class="progress-bar is-failed" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="100">
          <div class="progress-fill" style="width: 100%"></div>
        </div>
      </div>
    `;
  }

  if (typeof progress === "number" && !Number.isNaN(progress)) {
    const clamped = Math.min(99, Math.max(0, Math.round(progress)));
    return `
      <div class="progress-row status-progress">
        <div class="progress-label">${label}</div>
        <div class="progress-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${clamped}">
          <div class="progress-fill" style="width: ${clamped}%"></div>
        </div>
      </div>
    `;
  }

  return `
    <div class="progress-row status-progress">
      <div class="progress-label">${label}</div>
      <div class="progress-bar is-indeterminate" role="progressbar" aria-valuemin="0" aria-valuemax="100"></div>
    </div>
  `;
}

function renderFiles(files, jobId) {
  if (!files || files.length === 0) {
    return "<p class=\"hint\">No files yet.</p>";
  }
  const base = getApiBase();
  const normalized = files.map((file) => {
    let mode = file && file.mode ? String(file.mode) : "run";
    let name = file && file.name ? String(file.name) : "output";
    const path = file && file.path ? String(file.path) : "";
    if (!file || !file.mode) {
      const match = name.match(/^([a-z0-9_-]+)\s+-\s+(.+)$/i);
      if (match) {
        mode = match[1];
        name = match[2];
      }
    }
    return { mode, name, path };
  });
  const groups = new Map();
  normalized.forEach((file) => {
    const mode = file.mode || "run";
    if (!groups.has(mode)) {
      groups.set(mode, []);
    }
    groups.get(mode).push(file);
  });
  const totalCount = normalized.length;
  const searchValue = fileSearchTerms.get(jobId) || "";
  const controls = `
    <div class="files-controls">
      <input class="file-search" data-job-id="${jobId}" type="search" placeholder="Search files" value="${escapeHtml(searchValue)}" aria-label="Search files" />
      <div class="file-count" data-job-id="${jobId}">${totalCount} files</div>
    </div>
  `;
  const groupHtml = Array.from(groups.entries())
    .map(([mode, group]) => {
      const key = `${jobId}:${mode}`;
      const isOpen = fileGroupOpenState.get(key) === true;
      const rows = group
        .map((file) => {
          const name = file.name || "output";
          const pathRaw = file.path || "";
          const path = encodeURIComponent(pathRaw);
          const displayPath = pathRaw && pathRaw !== name ? pathRaw : "";
          return `
            <div class="file-row" data-job-id="${jobId}" data-mode="${escapeHtml(mode)}" data-name="${escapeHtml(
              name
            )}" data-path="${escapeHtml(pathRaw)}">
              <div class="file-meta">
                <div class="file-name">${escapeHtml(name)}</div>
                ${displayPath ? `<div class="file-path">${escapeHtml(displayPath)}</div>` : ""}
              </div>
              <div class="file-actions">
                <a class="file-link" href="${base}/jobs/${jobId}/files?path=${path}">Download</a>
              </div>
            </div>
          `;
        })
        .join("");
      return `
        <div class="file-group" data-job-id="${jobId}" data-mode="${escapeHtml(mode)}">
          <button class="file-group-header" type="button" data-job-id="${jobId}" data-mode="${escapeHtml(
            mode
          )}" aria-expanded="${isOpen ? "true" : "false"}">
            <span class="file-group-title">${escapeHtml(mode.toUpperCase())}</span>
            <span class="file-group-meta">${group.length} files</span>
          </button>
          <div class="file-group-body" ${isOpen ? "" : "hidden"}>
            ${rows}
          </div>
        </div>
      `;
    })
    .join("");
  return `
    ${controls}
    <div class="files-scroll" data-job-id="${jobId}">
      <div class="files-empty hint" data-job-id="${jobId}" hidden>No matching files.</div>
      ${groupHtml}
    </div>
  `;
}

function renderRunnerLog(job, base) {
  if (!job.output_root) return "";
  const logPath = `${job.output_root}/runner.log`;
  const logUrl = `${base}/jobs/${job.id}/files?path=${encodeURIComponent(logPath)}`;
  const isOpen = logOpenState.get(job.id) === true;
  return `
    <div class="log-entry" data-job-id="${job.id}" data-log-url="${logUrl}">
      <div class="log-header">
        <div class="log-title">Runner Log</div>
        <div class="log-actions">
          <button class="secondary log-toggle" type="button">${isOpen ? "Hide log" : "View log"}</button>
          <a class="log-download" href="${logUrl}">Download</a>
        </div>
      </div>
      <pre class="log-body" ${isOpen ? "" : "hidden"}></pre>
      <p class="hint log-hint" ${isOpen ? "" : "hidden"}>Loading...</p>
    </div>
  `;
}

async function fetchRunnerLog(jobId, url) {
  if (logCache.has(jobId)) return logCache.get(jobId);
  if (logFetches.has(jobId)) return logFetches.get(jobId);
  const fetchPromise = fetch(url)
    .then((resp) => {
      if (!resp.ok) throw new Error("Failed to fetch runner log");
      return resp.text();
    })
    .then((text) => {
      logCache.set(jobId, text);
      return text;
    })
    .finally(() => {
      logFetches.delete(jobId);
    });
  logFetches.set(jobId, fetchPromise);
  return fetchPromise;
}

function wireRunnerLog(job) {
  const entry = scanDetails.querySelector(".log-entry");
  if (!entry) return;
  const jobId = entry.dataset.jobId;
  const logUrl = entry.dataset.logUrl;
  const button = entry.querySelector(".log-toggle");
  const body = entry.querySelector(".log-body");
  const hint = entry.querySelector(".log-hint");

  const showLog = async () => {
    body.removeAttribute("hidden");
    button.textContent = "Hide log";
    logOpenState.set(jobId, true);
    if (logCache.has(jobId)) {
      body.textContent = logCache.get(jobId);
      hint.setAttribute("hidden", "");
      return;
    }
    hint.removeAttribute("hidden");
    try {
      const text = await fetchRunnerLog(jobId, logUrl);
      body.textContent = text;
    } catch (err) {
      body.textContent = err.message || "Failed to load runner log.";
    } finally {
      hint.setAttribute("hidden", "");
    }
  };

  const hideLog = () => {
    body.setAttribute("hidden", "");
    hint.setAttribute("hidden", "");
    button.textContent = "View log";
    logOpenState.set(jobId, false);
  };

  button.addEventListener("click", () => {
    const isOpen = !body.hasAttribute("hidden");
    if (isOpen) {
      hideLog();
    } else {
      showLog();
    }
  });

  if (logOpenState.get(jobId) === true) {
    showLog();
  } else {
    hideLog();
  }
}

function applyFileFilter(jobId, query) {
  const container = scanDetails.querySelector(`.files-scroll[data-job-id="${jobId}"]`);
  if (!container) return;
  const term =
    query !== undefined
      ? String(query).trim().toLowerCase()
      : String(fileSearchTerms.get(jobId) || "").trim().toLowerCase();
  const rows = Array.from(container.querySelectorAll(`.file-row[data-job-id="${jobId}"]`));
  let visibleCount = 0;
  rows.forEach((row) => {
    const haystack = `${row.dataset.name || ""} ${row.dataset.path || ""} ${row.dataset.mode || ""}`.toLowerCase();
    const match = !term || haystack.includes(term);
    row.toggleAttribute("hidden", !match);
    if (match) visibleCount += 1;
  });

  const groups = Array.from(container.querySelectorAll(`.file-group[data-job-id="${jobId}"]`));
  groups.forEach((group) => {
    const groupRows = Array.from(group.querySelectorAll(".file-row"));
    const visibleInGroup = groupRows.filter((row) => !row.hasAttribute("hidden")).length;
    const hasMatches = visibleInGroup > 0;
    group.toggleAttribute("hidden", !hasMatches);

    const meta = group.querySelector(".file-group-meta");
    if (meta) {
      meta.textContent = term ? `${visibleInGroup} of ${groupRows.length} files` : `${groupRows.length} files`;
    }

    const body = group.querySelector(".file-group-body");
    const header = group.querySelector(".file-group-header");
    if (body && header) {
      if (term) {
        body.removeAttribute("hidden");
        header.setAttribute("aria-expanded", "true");
      } else {
        const key = `${jobId}:${group.dataset.mode || ""}`;
        const isOpen = fileGroupOpenState.get(key) === true;
        body.toggleAttribute("hidden", !isOpen);
        header.setAttribute("aria-expanded", isOpen ? "true" : "false");
      }
    }
  });

  const count = scanDetails.querySelector(`.file-count[data-job-id="${jobId}"]`);
  if (count) {
    count.textContent = term ? `Showing ${visibleCount} of ${rows.length}` : `${rows.length} files`;
  }

  const empty = scanDetails.querySelector(`.files-empty[data-job-id="${jobId}"]`);
  if (empty) {
    empty.toggleAttribute("hidden", visibleCount !== 0);
  }
}

function wireFileGroups(jobId) {
  const headers = scanDetails.querySelectorAll(`.file-group-header[data-job-id="${jobId}"]`);
  headers.forEach((header) => {
    const mode = header.dataset.mode || "";
    const key = `${jobId}:${mode}`;
    header.addEventListener("click", () => {
      const group = header.closest(".file-group");
      if (!group) return;
      const body = group.querySelector(".file-group-body");
      if (!body) return;
      const isOpen = !body.hasAttribute("hidden");
      if (isOpen) {
        body.setAttribute("hidden", "");
        header.setAttribute("aria-expanded", "false");
        fileGroupOpenState.set(key, false);
      } else {
        body.removeAttribute("hidden");
        header.setAttribute("aria-expanded", "true");
        fileGroupOpenState.set(key, true);
      }
      applyFileFilter(jobId);
    });
  });
}

function wireFileSearch(jobId) {
  const input = scanDetails.querySelector(`.file-search[data-job-id="${jobId}"]`);
  if (!input) return;
  const applySearch = () => {
    fileSearchTerms.set(jobId, input.value || "");
    applyFileFilter(jobId, input.value || "");
  };
  input.addEventListener("input", applySearch);
  applyFileFilter(jobId, input.value || "");
}

function renderTargetList(title, items) {
  if (!items || items.length === 0) {
    return `
      <div class="detail-section">
        <h4>${title}</h4>
        <p class="hint">None</p>
      </div>
    `;
  }
  const rows = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  return `
    <div class="detail-section">
      <h4>${title}</h4>
      <ul class="detail-list">${rows}</ul>
    </div>
  `;
}

function renderApiKeys(targets) {
  const details = targets.api_key_details;
  if (Array.isArray(details) && details.length) {
    const rows = details
      .map((item) => {
        const kinds = (item.kinds || []).length
          ? item.kinds.map((kind) => kind.replace(/_/g, " ")).join(", ")
          : "unknown";
        const sources = (item.sources || []).join(", ");
        const resources = (item.resources || []).join(", ");
        const detectors = (item.detectors || []).length
          ? item.detectors.map((det) => det.replace(/_/g, " ")).join(", ")
          : "";
        const metaParts = [];
        if (kinds) metaParts.push(`type: ${kinds}`);
        if (resources) metaParts.push(`resource: ${resources}`);
        if (sources) metaParts.push(`source: ${sources}`);
        if (detectors) metaParts.push(`detected by: ${detectors}`);
        const meta = metaParts.join(" · ");
        return `
          <li class="key-row">
            <div class="key-value">${escapeHtml(item.key)}</div>
            ${meta ? `<div class="key-meta">${escapeHtml(meta)}</div>` : ""}
          </li>
        `;
      })
      .join("");
    return `
      <div class="detail-section">
        <h4>API Keys</h4>
        <ul class="detail-list api-keys">${rows}</ul>
      </div>
    `;
  }
  return renderTargetList("API Keys", targets.api_keys);
}

function renderChecks(title, checks) {
  if (!checks || checks.length === 0) {
    return `
      <div class="detail-section">
        <h4>${title}</h4>
        <p class="hint">No checks yet.</p>
      </div>
    `;
  }

  const header = `
    <div class="detail-row header">
      <span>Target</span>
      <span>Read</span>
      <span>Write</span>
      <span>Read Code</span>
      <span>Write Code</span>
      <span>Error</span>
    </div>
  `;

  const rows = checks
    .map((check) => {
      const read = check.read === true ? "Yes" : check.read === false ? "No" : "-";
      const write = check.write === true ? "Yes" : check.write === false ? "No" : "-";
      return `
        <div class="detail-row">
          <span>${escapeHtml(check.target)}</span>
          <span>${read}</span>
          <span>${write}</span>
          <span>${check.read_status ?? "-"}</span>
          <span>${check.write_status ?? "-"}</span>
          <span>${escapeHtml(check.error || "-")}</span>
        </div>
      `;
    })
    .join("");

  return `
    <div class="detail-section">
      <h4>${title}</h4>
      <div class="detail-table">
        ${header}
        ${rows}
      </div>
    </div>
  `;
}

function renderSecrets(secrets) {
  if (!secrets || secrets.enabled === false) {
    return `
      <div class="detail-section">
        <h4>Secrets</h4>
        <p class="hint">Secrets scan disabled.</p>
      </div>
    `;
  }
  if (secrets.error) {
    return `
      <div class="detail-section">
        <h4>Secrets</h4>
        <p class="hint">${escapeHtml(secrets.error)}</p>
      </div>
    `;
  }
  const findings = secrets.findings || [];
  if (findings.length === 0) {
    return `
      <div class="detail-section">
        <h4>Secrets</h4>
        <p class="hint">No secrets detected.</p>
      </div>
    `;
  }
  const header = `
    <div class="detail-row header">
      <span>Detector</span>
      <span>Type</span>
      <span>Severity</span>
      <span>Verified</span>
      <span>File</span>
      <span>Line</span>
      <span>Match</span>
    </div>
  `;
  const rows = findings
    .map((item) => {
      const verified = item.verified ? "Yes" : "No";
      const matchValue = item.match || item.redacted || "-";
      const dataAttrs =
        item.match || !item.file || item.line === undefined || item.line === null
          ? ""
          : ` data-match-path="${escapeAttr(item.file)}" data-match-line="${escapeAttr(
              item.line
            )}" data-match-detector="${escapeAttr(item.detector || "")}"`;
      return `
        <div class="detail-row">
          <span>${escapeHtml(item.detector || "-")}</span>
          <span>${escapeHtml(item.type || "-")}</span>
          <span>${escapeHtml(item.severity || "-")}</span>
          <span>${verified}</span>
          <span>${escapeHtml(item.file || "-")}</span>
          <span>${item.line ?? "-"}</span>
          <span class="secret-match"${dataAttrs}>${escapeHtml(matchValue)}</span>
        </div>
      `;
    })
    .join("");
  const truncated = secrets.truncated
    ? `<p class="hint">Showing first ${findings.length} of ${secrets.count} findings.</p>`
    : "";
  return `
    <div class="detail-section">
      <h4>Secrets</h4>
      ${truncated}
      <div class="detail-table secrets-table">
        ${header}
        ${rows}
      </div>
    </div>
  `;
}

async function loadModeDetails(job, mode, packageName) {
  const files = job.files || [];
  let file = null;
  if (packageName) {
    file = files.find(
      (item) => item.mode === mode && item.name === `${packageName}/scan.json`
    );
    if (!file) {
      file = files.find((item) => {
        if (item.mode !== mode || !item.path) return false;
        return item.path.includes(`/${packageName}/`) && item.path.endsWith("/scan.json");
      });
    }
  }
  if (!file) {
    file = files.find((item) => item.mode === mode && item.name === "scan.json");
  }
  if (!file) {
    return `
      <div class="mode-block">
        <h3>${mode.toUpperCase()}</h3>
        <p class="hint">Scan results not available yet.</p>
      </div>
    `;
  }
  const base = getApiBase();
  const resp = await fetch(`${base}/jobs/${job.id}/files?path=${encodeURIComponent(file.path)}`);
  if (!resp.ok) {
    return `
      <div class="mode-block">
        <h3>${mode.toUpperCase()}</h3>
        <p class="hint">Failed to load scan.json.</p>
      </div>
    `;
  }
  const scan = await resp.json();
  const targets = scan.targets || {};
  const auth = scan.auth || {};
  const services = scan.services || {};
  const rtdb = services.rtdb || {};
  const firestore = services.firestore || {};
  const storage = services.storage || {};
  const secrets = scan.secrets || {};

  return `
    <div class="mode-block">
      <h3>${mode.toUpperCase()}</h3>
      <div class="detail-section">
        <h4>Auth</h4>
        <div class="detail-meta-grid">
          <div><span>Enabled</span><strong>${auth.enabled ? "Yes" : "No"}</strong></div>
          <div><span>Success</span><strong>${auth.success ? "Yes" : "No"}</strong></div>
          <div><span>Error</span><strong>${escapeHtml(auth.error || "-")}</strong></div>
          <div><span>Email</span><strong>${escapeHtml(auth.email || "-")}</strong></div>
        </div>
      </div>
      ${renderTargetList("Project IDs", targets.project_ids)}
      ${renderApiKeys(targets)}
      ${renderTargetList("App IDs", targets.app_ids)}
      ${renderTargetList("Database URLs", targets.database_urls)}
      ${renderTargetList("Storage Buckets", targets.storage_buckets)}
      ${renderSecrets(secrets)}
      ${renderChecks("Realtime Database Checks", rtdb.checks)}
      ${renderChecks("Firestore Checks", firestore.checks)}
      ${renderChecks("Storage Checks", storage.checks)}
    </div>
  `;
}

function getScanId() {
  const url = new URL(window.location.href);
  return url.searchParams.get("id");
}

function getPackageParam() {
  const url = new URL(window.location.href);
  const value = url.searchParams.get("package");
  return isPackageName(value) ? value : null;
}

function getModeParam() {
  const url = new URL(window.location.href);
  return url.searchParams.get("mode");
}

async function loadScan() {
  const id = getScanId();
  if (!id) {
    detailHint.textContent = "Missing scan ID. Use the Scans page to open a scan.";
    return;
  }
  const selectedPackage = getPackageParam();
  const selectedMode = getModeParam();
  const base = getApiBase();
  if (scanLoadProgress) {
    scanLoadProgress.removeAttribute("hidden");
    if (scanLoadProgressLabel) {
      scanLoadProgressLabel.textContent = "Loading scan details...";
    }
    const bar = scanLoadProgress.querySelector(".progress-bar");
    if (bar) {
      bar.classList.remove("is-failed", "is-complete");
      bar.classList.add("is-indeterminate");
      const fill = bar.querySelector(".progress-fill");
      if (fill) fill.remove();
    }
  }
  try {
    const [jobResp, apksResp] = await Promise.all([
      fetch(`${base}/jobs/${id}`),
      fetch(`${base}/apks`),
    ]);
    if (!jobResp.ok) {
      throw new Error("Failed to fetch scan details");
    }
    const job = await jobResp.json();
    const apks = apksResp.ok ? await apksResp.json() : [];
    const apk = apks.find((item) => item.job_id === job.id);

    if (selectedPackage && ["aurora_random", "search"].includes(getScanSource(job))) {
      let foundEntry = false;
      try {
        const batchResp = await fetch(`${base}/jobs/${job.id}/batch`);
        if (batchResp.ok) {
          const batch = await batchResp.json();
          const entries = (batch || []).filter((item) => {
            if (!item || item.package_name !== selectedPackage) return false;
            if (selectedMode && item.mode && item.mode !== selectedMode) return false;
            return true;
          });
          if (entries.length) {
            foundEntry = true;
            const summaryByMode = {};
            const prefixes = [];
            const outputRoot = job.output_root ? String(job.output_root).replace(/\/+$/, "") : "";
            entries.forEach((entry) => {
              const mode = entry.mode || "unauth";
              summaryByMode[mode] = entry.summary || [];
              if (entry.results_dir) {
                let resolved = String(entry.results_dir);
                if (!resolved.startsWith("/") && outputRoot) {
                  resolved = `${outputRoot}/${resolved}`;
                }
                prefixes.push(resolved.replace(/\/+$/, "") + "/");
              }
            });
            job.package_name = selectedPackage;
            job.summary = summaryByMode;
            if (prefixes.length) {
              const filtered = (job.files || []).filter((file) => {
                const path = file.path || "";
                return prefixes.some((prefix) => path.startsWith(prefix));
              });
              if (filtered.length) {
                job.files = filtered;
              }
            }
            if (!job.files || job.files.length === 0) {
              const token = `/${selectedPackage}/`;
              job.files = (job.files || []).filter((file) => {
                const path = file.path || "";
                return path.includes(token);
              });
            }
          }
        }
      } catch (err) {
        console.error("Failed to load batch entry", err);
      }
      if (!foundEntry) {
        job.package_name = selectedPackage;
      }
    }

    detailHint.textContent = "";
    const status = getEffectiveStatus(job);
    const source = getScanSource(job);
    if (status === "failed") {
      console.error("Scan failed", job.error || "No error message provided.");
    } else if (job.error) {
      console.error("Scan reported error", job.error);
    }
    const filesHtml = renderFiles(job.files || [], job.id);
    const summaryHtml = renderSummaryBlocks(job.summary);
    const statusProgressHtml = renderStatusProgress(
      status,
      job.progress,
      job.progress_stage,
      job.progress_mode
    );
    const logHtml = renderRunnerLog(job, base);
    const apkActionsHtml = renderApkActions(job, apk);

    let modes = Array.from(
      new Set(
        (job.files || [])
          .map((file) => file.mode)
          .filter((mode) => mode)
      )
    );
    if (selectedMode) {
      modes = [selectedMode];
    } else if (selectedPackage && modes.length === 0) {
      modes = ["unauth"];
    }
    const modeBlocks = await Promise.all(
      (modes.length ? modes : ["unauth"]).map((mode) =>
        loadModeDetails(job, mode, selectedPackage)
      )
    );

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
          <div><span>Source</span><strong>${formatSourceLabel(source)}</strong></div>
          <div><span>Auth Scan</span><strong>${job.auth_enabled ? "Yes" : "No"}</strong></div>
          <div><span>Write Tests</span><strong>${job.write_enabled ? "Yes" : "No"}</strong></div>
          <div><span>Scan Rate</span><strong>${job.scan_rate}</strong></div>
          <div><span>APK Path</span><strong>${job.apk_path || "-"}</strong></div>
        </div>
        ${job.error ? `<p class="hint" style="color: var(--danger);">Error: ${escapeHtml(job.error)}</p>` : ""}
        <div class="details-meta">
          <div><span>APK Size</span><strong>${apk ? formatSize(apk.size) : "-"}</strong></div>
          <div><span>APK Modified</span><strong>${apk ? formatDate(apk.modified_at) : "-"}</strong></div>
          <div><span>APK File</span><strong>${apk ? escapeHtml(apk.name) : "-"}</strong></div>
        </div>
        <div class="summary">${summaryHtml}</div>
        ${apkActionsHtml}
        <div class="files">
          <div class="files-list">
            ${logHtml}
            ${filesHtml}
          </div>
        </div>
        ${statusProgressHtml}
      </div>
      ${modeBlocks.join("")}
    `;
    if (scanLoadProgress) {
      scanLoadProgress.setAttribute("hidden", "");
    }
    wireRunnerLog(job);
    wireApkRestore(job, base);
    wireDeleteScan(job, base);
    wireStopScan(job, base);
    hydrateSecretMatches(job, base);
  } catch (err) {
    console.error("Failed to load scan details", err);
    scanDetails.innerHTML = `<p class="hint">Failed to load scan details.</p>`;
    if (scanLoadProgress) {
      if (scanLoadProgressLabel) {
        scanLoadProgressLabel.textContent = "Failed to load scan details.";
      }
      const bar = scanLoadProgress.querySelector(".progress-bar");
      if (bar) {
        bar.classList.remove("is-indeterminate");
        bar.classList.add("is-failed");
        if (!bar.querySelector(".progress-fill")) {
          const fill = document.createElement("div");
          fill.className = "progress-fill";
          fill.style.width = "100%";
          bar.appendChild(fill);
        }
      }
    }
  }
}

saveApiBaseButton.addEventListener("click", () => {
  const value = apiBaseInput.value.trim();
  if (value) {
    setApiBase(value);
    checkApi();
    loadScan();
  }
});

checkApi();
loadScan();
setInterval(() => {
  loadScan();
}, 15000);
