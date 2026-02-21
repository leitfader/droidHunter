const defaultApi = "http://localhost:8000";
const apiBaseInput = document.getElementById("apiBase");
const apiStatus = document.getElementById("apiStatus");
const saveApiBaseButton = document.getElementById("saveApiBase");
const scansList = document.getElementById("scansList");
const scanSearch = document.getElementById("scanSearch");
const statusFilter = document.getElementById("statusFilter");
const sourceFilter = document.getElementById("sourceFilter");
const refreshScansButton = document.getElementById("refreshScans");

let currentJobs = [];

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

function toNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function hasPositiveCount(counts, key) {
  return toNumber(counts?.[key]) > 0;
}

function getSummaryItems(summary) {
  if (!summary) return [];
  if (Array.isArray(summary)) return summary;
  if (typeof summary === "object") {
    return Object.values(summary).flatMap((items) => (Array.isArray(items) ? items : []));
  }
  return [];
}

function isCriticalSummary(summary) {
  const items = getSummaryItems(summary);
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const title = String(item.title || "").toLowerCase();
    const counts = item.counts || {};
    if (title === "secrets") {
      if (hasPositiveCount(counts, "Findings") || hasPositiveCount(counts, "Verified")) {
        return true;
      }
    }
    if (title.includes("database") || title.includes("firestore") || title.includes("storage")) {
      if (hasPositiveCount(counts, "Writable") || hasPositiveCount(counts, "Readable")) {
        return true;
      }
    }
  }
  return false;
}

function getScanSource(job) {
  if (job.scan_source) return job.scan_source;
  if (job.package_name) return "aurora";
  if (job.apk_path) return "local";
  if (job.output_root) return "project";
  return "unknown";
}

function formatProgressStage(stage, mode) {
  if (!stage) return "";
  const normalized = stage.replace(/_/g, " ");
  if (mode) {
    return `${normalized} (${mode})`;
  }
  return normalized;
}

function isPackageName(value) {
  if (!value) return false;
  return /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(String(value));
}

function getWaitingLabel(job) {
  const stage = formatProgressStage(job.progress_stage, job.progress_mode);
  if (stage) {
    return `Waiting: ${stage}`;
  }
  return "Waiting for first app...";
}

function formatSourceLabel(source) {
  const map = {
    aurora: "SEARCHED",
    aurora_random: "AUTOMATED POOL",
    local: "LOCAL",
    project: "PROJECT",
    apk_dir: "APK DIR",
    device: "DEVICE",
    download: "DOWNLOAD",
    unknown: "UNKNOWN",
  };
  return map[source] || String(source || "UNKNOWN").toUpperCase();
}

function getEffectiveStatus(job) {
  const baseStatus = job.status || "running";
  if (["failed", "completed", "stopped"].includes(baseStatus)) {
    return baseStatus;
  }
  return job.progress_status || baseStatus;
}

function renderScanRow(job) {
  const title = job.package_name || job.apk_path || "Job";
  const status = getEffectiveStatus(job);
  const source = getScanSource(job);
  const critical = isCriticalSummary(job.summary);
  const jobId = job.job_id || job.id;
  const packageParam = isPackageName(job.package_name)
    ? `&package=${encodeURIComponent(job.package_name)}`
    : "";
  const viewLink = `/scans/detail.html?id=${jobId}${packageParam}`;
  const isAutomated = getScanSource(job) === "aurora_random";
  const deleteDisabled = status === "running";
  const stopDisabled = status !== "running";
  return `
    <div class="scan-row${critical ? " critical" : ""}">
      <div class="scan-main">
        <div class="scan-title">${title}</div>
        <div class="scan-meta">${jobId}</div>
        <div class="scan-meta">${formatSourceLabel(source)} · ${formatDate(job.created_at)}</div>
      </div>
      <div class="scan-actions">
        <span class="status ${status}">${status}</span>
        ${critical ? `<span class="status critical">critical</span>` : ""}
        <a class="btn-link" href="${viewLink}">View</a>
        <button class="secondary stop-scan" data-job-id="${jobId}" ${
          stopDisabled ? "disabled" : ""
        }>Stop</button>
        <button class="danger delete-scan" data-job-id="${jobId}" data-package="${job.package_name || ""}" data-automated="${isAutomated ? "true" : "false"}" ${
          deleteDisabled ? "disabled" : ""
        }>Delete</button>
      </div>
    </div>
  `;
}

function renderList() {
  const query = (scanSearch.value || "").trim().toLowerCase();
  const status = statusFilter.value;
  const source = sourceFilter ? sourceFilter.value : "all";
  const filtered = currentJobs.filter((job) => {
    if (status !== "all" && getEffectiveStatus(job) !== status) {
      return false;
    }
    if (source !== "all") {
      const jobSource = getScanSource(job);
      if (source === "automated_pool") {
        if (jobSource !== "aurora_random") return false;
      } else if (jobSource !== source) {
        return false;
      }
    }
    if (!query) return true;
    const haystack = `${job.package_name || ""} ${job.apk_path || ""} ${job.job_id || ""} ${
      job.id || ""
    }`.toLowerCase();
    return haystack.includes(query);
  });

  if (filtered.length === 0) {
    scansList.innerHTML = `<p class="hint">No scans match the filter.</p>`;
    return;
  }

  scansList.innerHTML = filtered.map(renderScanRow).join("");
  wireDeleteButtons();
  wireStopButtons();
}

async function loadJobs() {
  const base = getApiBase();
  try {
    const resp = await fetch(`${base}/jobs`);
    if (!resp.ok) {
      throw new Error("Failed to fetch jobs");
    }
    const jobs = await resp.json();
    currentJobs = await expandJobs(jobs);
    renderList();
  } catch (err) {
    console.error("Failed to load scans", err);
    scansList.innerHTML = `<p class="hint">Failed to load scans. Check API URL.</p>`;
  }
}

async function expandJobs(jobs) {
  const base = getApiBase();
  const randomJobs = jobs.filter((job) => getScanSource(job) === "aurora_random");
  if (!randomJobs.length) {
    return jobs;
  }
  const batchMap = new Map();
  await Promise.all(
    randomJobs.map(async (job) => {
      const effectiveStatus = getEffectiveStatus(job);
      const isRunning = effectiveStatus === "running";
      try {
        const resp = await fetch(`${base}/jobs/${job.id}/batch`);
        if (!resp.ok) {
          throw new Error("Failed to fetch batch");
        }
        const batch = await resp.json();
        if (Array.isArray(batch) && batch.length) {
          const byPackage = new Map();
          for (const entry of batch) {
            if (!entry || !entry.package_name) continue;
            const name = entry.package_name;
            const mode = entry.mode || "unauth";
            let item = byPackage.get(name);
            if (!item) {
              const entryStatus = isRunning ? "completed" : effectiveStatus || "completed";
              item = {
                id: `${job.id}:${name}`,
                job_id: job.id,
                created_at: job.created_at,
                status: entryStatus,
                package_name: name,
                summary: {},
                scan_source: "aurora_random",
              };
              byPackage.set(name, item);
            }
            item.summary[mode] = entry.summary || [];
          }
          const entries = Array.from(byPackage.values());
          const progressPackage = isPackageName(job.progress_item) ? job.progress_item : "";
          if (isRunning && progressPackage) {
            const exists = entries.some((entry) => entry.package_name === progressPackage);
            if (!exists) {
              entries.unshift({
                id: `${job.id}:${progressPackage}`,
                job_id: job.id,
                created_at: job.created_at,
                status: "running",
                package_name: progressPackage,
                summary: {},
                scan_source: "aurora_random",
              });
            }
          }
          batchMap.set(job.id, entries);
          return;
        }
      } catch (err) {
        // ignore and fall back
      }
      const progressPackage = isPackageName(job.progress_item) ? job.progress_item : "";
      if (isRunning && progressPackage) {
        batchMap.set(job.id, [
          {
            id: `${job.id}:${progressPackage}`,
            job_id: job.id,
            created_at: job.created_at,
            status: "running",
            package_name: progressPackage,
            summary: [],
            scan_source: "aurora_random",
            mode: job.progress_mode,
          },
        ]);
      } else {
        batchMap.set(job.id, [
          {
            id: job.id,
            job_id: job.id,
            created_at: job.created_at,
            status: effectiveStatus,
            package_name: getWaitingLabel(job),
            summary: job.summary || [],
            scan_source: "aurora_random",
          },
        ]);
      }
    })
  );

  const expanded = [];
  for (const job of jobs) {
    if (getScanSource(job) === "aurora_random") {
      const items = batchMap.get(job.id) || [];
      expanded.push(...items);
    } else {
      expanded.push(job);
    }
  }
  return expanded;
}

function wireDeleteButtons() {
  document.querySelectorAll(".delete-scan").forEach((button) => {
    button.addEventListener("click", async () => {
      const jobId = button.dataset.jobId;
      const packageName = button.dataset.package || "";
      const automated = button.dataset.automated === "true";
      if (!jobId) return;
      const label = packageName ? ` ${packageName}` : "";
      const message = automated
        ? `Delete automated scan job${label}? This removes all results from this automated run.`
        : `Delete scan${label}? This removes all results.`;
      if (!confirm(message)) return;
      button.disabled = true;
      try {
        const base = getApiBase();
        const resp = await fetch(`${base}/jobs/${jobId}`, { method: "DELETE" });
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          throw new Error(data.detail || "Failed to delete scan.");
        }
        await loadJobs();
      } catch (err) {
        alert(err.message || "Failed to delete scan.");
        button.disabled = false;
      }
    });
  });
}

function wireStopButtons() {
  document.querySelectorAll(".stop-scan").forEach((button) => {
    button.addEventListener("click", async () => {
      const jobId = button.dataset.jobId;
      if (!jobId) return;
      if (!confirm("Stop this scan?")) return;
      button.disabled = true;
      try {
        const base = getApiBase();
        const resp = await fetch(`${base}/jobs/${jobId}/stop`, { method: "POST" });
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          throw new Error(data.detail || "Failed to stop scan.");
        }
        await loadJobs();
      } catch (err) {
        alert(err.message || "Failed to stop scan.");
        button.disabled = false;
      }
    });
  });
}

scanSearch.addEventListener("input", renderList);
statusFilter.addEventListener("change", renderList);
if (sourceFilter) {
  sourceFilter.addEventListener("change", renderList);
}
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
