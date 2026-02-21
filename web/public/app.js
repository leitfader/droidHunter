const defaultApi = "http://localhost:8000";
const apiBaseInput = document.getElementById("apiBase");
const apiStatus = document.getElementById("apiStatus");
const saveApiBaseButton = document.getElementById("saveApiBase");
const auroraForm = document.getElementById("auroraForm");
const randomForm = document.getElementById("randomForm");
const localForm = document.getElementById("localForm");
const projectForm = document.getElementById("projectForm");
const deviceForm = document.getElementById("deviceForm");
const scanOptionsForm = document.getElementById("scanOptions");
const apksList = document.getElementById("apksList");
const refreshApksButton = document.getElementById("refreshApks");
const startScanButton = document.getElementById("startScan");
const stopRandomScanButton = document.getElementById("stopRandomScan");
const deepScanPresetButton = document.getElementById("deepScanPreset");
const testTopChartsButton = document.getElementById("testTopCharts");
const testTopChartsResult = document.getElementById("testTopChartsResult");
const scanProgress = document.getElementById("scanProgress");
const scanProgressLabel = document.getElementById("scanProgressLabel");
const scanProgressBar = document.getElementById("scanProgressBar");
const scanProgressAction = document.getElementById("scanProgressAction");
const scanProgressDetail = document.getElementById("scanProgressDetail");
const scanProgressLog = document.getElementById("scanProgressLog");
const tabButtons = Array.from(document.querySelectorAll(".tab"));
const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));
let progressPoll = null;
let activeRandomJobId = localStorage.getItem("randomJobId") || null;
let scanInFlight = false;
let progressLog = [];
let lastProgressKey = null;
let currentScanDescription = "";

function formatProgressStage(stage, mode) {
  if (!stage) return "Running";
  const normalized = stage.replace(/_/g, " ");
  if (mode) {
    return `${normalized} (${mode})`;
  }
  return normalized;
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

function formToPayload(form) {
  if (!form) return {};
  const formData = new FormData(form);
  const payload = {};
  for (const [key, value] of formData.entries()) {
    if (value === "") continue;
    payload[key] = value;
  }

  const authEnabled = form.querySelector('input[name="auth_enabled"]');
  const writeEnabled = form.querySelector('input[name="write_enabled"]');
  const fastExtract = form.querySelector('input[name="fast_extract"]');
  const useJadx = form.querySelector('input[name="use_jadx"]');
  const jadxAutoInstall = form.querySelector('input[name="jadx_auto_install"]');
  const extractSignatures = form.querySelector('input[name="extract_signatures"]');
  const secretsScan = form.querySelector('input[name="secrets_scan"]');
  const readConfig = form.querySelector('input[name="read_config"]');
  const fuzzCollections = form.querySelector('input[name="fuzz_collections"]');
  const adbScan = form.querySelector('input[name="adb_scan"]');
  const auroraRandom = form.querySelector('input[name="aurora_random"]');
  const randomContinuous = form.querySelector('input[name="random_continuous"]');
  const keepApk = form.querySelector('input[name="keep_apk"]');
  if (authEnabled) payload.auth_enabled = authEnabled.checked;
  if (writeEnabled) payload.write_enabled = writeEnabled.checked;
  if (fastExtract) payload.fast_extract = fastExtract.checked;
  if (useJadx) payload.use_jadx = useJadx.checked;
  if (jadxAutoInstall) payload.jadx_auto_install = jadxAutoInstall.checked;
  if (extractSignatures) payload.extract_signatures = extractSignatures.checked;
  if (secretsScan) payload.secrets_scan = secretsScan.checked;
  if (readConfig) payload.read_config = readConfig.checked;
  if (fuzzCollections) payload.fuzz_collections = fuzzCollections.checked;
  if (adbScan) payload.adb_scan = adbScan.checked;
  if (auroraRandom) payload.aurora_random = auroraRandom.checked;
  if (randomContinuous) payload.random_continuous = randomContinuous.checked;
  if (keepApk) payload.keep_apk = keepApk.checked;

  if (payload.scan_rate) payload.scan_rate = parseFloat(payload.scan_rate);
  if (payload.processes) payload.processes = parseInt(payload.processes, 10);
  if (payload.timeout_minutes) payload.timeout_minutes = parseInt(payload.timeout_minutes, 10);
  if (payload.jadx_timeout_minutes) {
    payload.jadx_timeout_minutes = parseInt(payload.jadx_timeout_minutes, 10);
  }
  if (payload.random_count) payload.random_count = parseInt(payload.random_count, 10);
  if (payload.random_attempts) payload.random_attempts = parseInt(payload.random_attempts, 10);
  if (payload.random_chart_limit) payload.random_chart_limit = parseInt(payload.random_chart_limit, 10);
  if (payload.search_limit) payload.search_limit = parseInt(payload.search_limit, 10);
  return payload;
}

function getActivePanel() {
  return tabPanels.find((panel) => panel.classList.contains("active"));
}

function buildPayload(activeForm) {
  const options = formToPayload(scanOptionsForm);
  const primary = formToPayload(activeForm);
  return { ...options, ...primary };
}

function setActiveTab(tabId) {
  tabButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === tabId);
  });
  tabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.tab === tabId);
  });
  if (stopRandomScanButton) {
    stopRandomScanButton.toggleAttribute("hidden", tabId !== "random");
  }
}

function formatSize(bytes) {
  if (!bytes && bytes !== 0) return "-";
  const mb = bytes / (1024 * 1024);
  return `${mb.toFixed(2)} MB`;
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch (e) {
    return iso;
  }
}

function renderApks(apks) {
  if (!apks || apks.length === 0) {
    return "<p class=\"hint\">No APKs yet.</p>";
  }
  return apks
    .map((apk) => {
      const title = apk.package_name || apk.name;
      const source = apk.aurora_mode ? apk.aurora_mode.toUpperCase() : "LOCAL";
      return `
        <div class="list-item">
          <div class="meta">
            <div class="title">${title}</div>
            <div>${source} · ${formatSize(apk.size)} · ${formatDate(apk.modified_at)}</div>
          </div>
          <div class="list-actions">
            <button class="secondary use-apk" data-path="${apk.path}">Use</button>
            <button class="scan-apk" data-path="${apk.path}">Scan</button>
          </div>
        </div>
      `;
    })
    .join("");
}

function setScanProgress(visible, label) {
  if (!scanProgress) return;
  if (visible) {
    const wasHidden = scanProgress.hasAttribute("hidden");
    scanProgress.removeAttribute("hidden");
    if (scanProgressLabel && label) {
      scanProgressLabel.textContent = label;
    }
    if (scanProgressBar) {
      scanProgressBar.classList.add("is-indeterminate");
    }
    if (scanProgressAction) {
      scanProgressAction.innerHTML = "";
    }
    if (wasHidden) {
      resetVerboseOutput();
    }
  } else {
    scanProgress.setAttribute("hidden", "");
    resetVerboseOutput();
  }
}

function updateProgressBar(status, progress, stage, mode) {
  if (!scanProgressBar || !scanProgressLabel) return;
  const labelParts = [status];
  if (stage) {
    labelParts.push(formatProgressStage(stage, mode));
  }
  const hasProgress = progress !== null && progress !== undefined && progress !== "";
  const progressValue = hasProgress ? Number(progress) : Number.NaN;
  if (Number.isFinite(progressValue)) {
    const clamped = Math.min(100, Math.max(0, Math.round(progressValue)));
    labelParts.push(`${clamped}%`);
    scanProgressBar.classList.remove("is-indeterminate");
    scanProgressBar.classList.toggle("is-complete", status === "completed");
    scanProgressBar.classList.toggle("is-failed", status === "failed");
    scanProgressBar.classList.toggle("is-stopped", status === "stopped");
    let fill = scanProgressBar.querySelector(".progress-fill");
    if (!fill) {
      fill = document.createElement("div");
      fill.className = "progress-fill";
      scanProgressBar.appendChild(fill);
    }
    fill.style.width = `${clamped}%`;
    scanProgressBar.setAttribute("aria-valuenow", clamped);
  } else {
    scanProgressBar.classList.add("is-indeterminate");
    const fill = scanProgressBar.querySelector(".progress-fill");
    if (fill) fill.remove();
  }
  scanProgressLabel.textContent = labelParts.join(" · ");
}

function resetVerboseOutput() {
  if (scanProgressDetail) {
    scanProgressDetail.textContent = "";
  }
  if (scanProgressLog) {
    scanProgressLog.innerHTML = "";
  }
  progressLog = [];
  lastProgressKey = null;
  currentScanDescription = "";
}

function appendProgressLog(message) {
  if (!scanProgressLog) return;
  const time = new Date().toLocaleTimeString();
  progressLog.push({ time, message });
  if (progressLog.length > 6) {
    progressLog = progressLog.slice(progressLog.length - 6);
  }
  scanProgressLog.innerHTML = progressLog
    .map(
      (entry) =>
        `<div class="log-entry"><span class="log-time">${escapeHtml(entry.time)}</span><span>${escapeHtml(
          entry.message
        )}</span></div>`
    )
    .join("");
}

function setProgressDetail(message) {
  if (!scanProgressDetail) return;
  scanProgressDetail.textContent = message || "";
}

function describeScanPayload(payload) {
  if (payload.aurora_random) {
    return "Aurora Random (automated pool)";
  }
  if (payload.adb_scan) {
    return payload.adb_serial ? `ADB Device (${payload.adb_serial})` : "ADB Device";
  }
  if (payload.apk_dir) {
    return `APK directory: ${payload.apk_dir}`;
  }
  if (payload.project_id || payload.project_id_file || payload.dns_file || payload.resume_path) {
    if (payload.project_id) return `Project IDs: ${payload.project_id}`;
    if (payload.project_id_file) return `Project ID file: ${payload.project_id_file}`;
    if (payload.dns_file) return `DNS file: ${payload.dns_file}`;
    if (payload.resume_path) return `Resume from: ${payload.resume_path}`;
    return "Project scan";
  }
  if (payload.apk_path) {
    return `Local APK: ${payload.apk_path}`;
  }
  if (payload.package_name) {
    return `Aurora search: ${payload.package_name}`;
  }
  return "Scan";
}

function updateVerboseProgress(job) {
  if (!job) return;
  const status = job.progress_status || job.status || "running";
  const stageLabel = formatProgressStage(job.progress_stage || status, job.progress_mode);
  const item = job.progress_item ? ` · ${job.progress_item}` : "";
  const prefix = currentScanDescription ? `${currentScanDescription} · ` : "";
  const detail = `${prefix}${stageLabel}${item}`;
  setProgressDetail(detail);
  const key = `${status}|${job.progress_stage || ""}|${job.progress_mode || ""}|${job.progress_item || ""}`;
  if (key !== lastProgressKey) {
    appendProgressLog(`${status} · ${detail}`);
    lastProgressKey = key;
  }
  if (status === "failed" && job.error) {
    appendProgressLog(`Error: ${job.error}`);
    setProgressDetail(`Error: ${job.error}`);
  }
}

function setOptionChecked(name, checked) {
  if (!scanOptionsForm) return;
  const input = scanOptionsForm.querySelector(`input[name="${name}"]`);
  if (input && input.type === "checkbox") {
    input.checked = checked;
  }
}

function applyDeepScanPreset() {
  setOptionChecked("fast_extract", false);
  [
    "use_jadx",
    "jadx_auto_install",
    "extract_signatures",
    "secrets_scan",
    "read_config",
    "fuzz_collections",
  ].forEach((name) => setOptionChecked(name, true));
}

async function testTopCharts() {
  if (!randomForm || !testTopChartsButton) return;
  const base = getApiBase();
  const payload = formToPayload(randomForm);
  const request = {
    chart: payload.random_chart || "TOP_SELLING_FREE",
    chart_type: payload.random_chart_type || "APPLICATION",
    chart_limit: payload.random_chart_limit || 10,
    dispenser_url: payload.dispenser_url,
    device_props: payload.device_props,
    locale: payload.locale,
  };
  if (testTopChartsResult) {
    testTopChartsResult.textContent = "Checking top charts...";
  }
  testTopChartsButton.disabled = true;
  try {
    const resp = await fetch(`${base}/aurora/top-charts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "Failed to load top charts.");
    }
    const data = await resp.json();
    const packages = Array.isArray(data.packages) ? data.packages : [];
    if (testTopChartsResult) {
      if (packages.length === 0) {
        testTopChartsResult.textContent = "Top charts returned no packages.";
      } else {
        testTopChartsResult.textContent = `Top charts OK: ${packages.slice(0, 5).join(", ")}${packages.length > 5 ? "…" : ""}`;
      }
    }
  } catch (err) {
    if (testTopChartsResult) {
      testTopChartsResult.textContent = err.message || "Top charts test failed.";
    }
  } finally {
    testTopChartsButton.disabled = false;
  }
}

async function pollJobProgress(jobId) {
  if (progressPoll) {
    clearInterval(progressPoll);
  }
  const base = getApiBase();
  const detailUrl = `/scans/detail.html?id=${jobId}`;
  if (scanProgressAction) {
    scanProgressAction.innerHTML = `<a href="${detailUrl}">View Scan</a>`;
  }

  const tick = async () => {
    try {
      const resp = await fetch(`${base}/jobs/${jobId}`);
      if (!resp.ok) {
        throw new Error("Failed to fetch job status");
      }
      const job = await resp.json();
      const status = job.progress_status || job.status || "running";
      updateProgressBar(status, job.progress, job.progress_stage, job.progress_mode);
      updateVerboseProgress(job);

      if (status === "completed" || status === "failed" || status === "stopped") {
        clearInterval(progressPoll);
        progressPoll = null;
        startScanButton.disabled = false;
        startScanButton.textContent = "Start Scan";
        scanInFlight = false;
        appendProgressLog(`Scan ${status}.`);
        if (activeRandomJobId === jobId) {
          localStorage.removeItem("randomJobId");
          activeRandomJobId = null;
        }
      }
    } catch (err) {
      console.error("Failed to poll job progress", err);
    }
  };

  await tick();
  progressPoll = setInterval(tick, 2500);
}

async function submitScan(payload, resetForm) {
  if (scanInFlight) {
    alert("A scan is already running.");
    return;
  }
  scanInFlight = true;
  const base = getApiBase();
  const originalLabel = startScanButton.textContent;
  startScanButton.disabled = true;
  startScanButton.textContent = "Starting...";
  resetVerboseOutput();
  setScanProgress(true, "Submitting scan...");
  const scanDescription = describeScanPayload(payload);
  currentScanDescription = scanDescription;
  setProgressDetail(scanDescription);
  appendProgressLog(`Submitting ${scanDescription}...`);
  try {
    const resp = await fetch(`${base}/jobs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) {
      const errorData = await resp.json();
      throw new Error(errorData.detail || "Failed to create job");
    }
    const job = await resp.json();
    if (resetForm) resetForm.reset();
    setScanProgress(true, "Scan started. Tracking progress...");
    appendProgressLog(`Job created: ${job.id}`);
    appendProgressLog("Scan started. Tracking progress...");
    if (payload.aurora_random) {
      activeRandomJobId = job.id;
      localStorage.setItem("randomJobId", job.id);
    }
    await pollJobProgress(job.id);
  } catch (err) {
    console.error("Start scan failed", err);
    alert(err.message);
    setScanProgress(true, "Scan failed to start");
    updateProgressBar("failed", 100, "request_failed");
    setProgressDetail(err.message || "Failed to start scan.");
    appendProgressLog(`Error: ${err.message || "Failed to start scan."}`);
    startScanButton.disabled = false;
    startScanButton.textContent = originalLabel;
    scanInFlight = false;
  }
}

async function startScan() {
  const activePanel = getActivePanel();
  const payload = buildPayload(activePanel);
  await submitScan(payload, activePanel);
}

async function stopRandomScan() {
  const base = getApiBase();
  const jobId = activeRandomJobId || localStorage.getItem("randomJobId");
  if (!jobId) {
    alert("No active random scan found.");
    return;
  }
  if (stopRandomScanButton) {
    stopRandomScanButton.disabled = true;
    stopRandomScanButton.textContent = "Stopping...";
  }
  try {
    const resp = await fetch(`${base}/jobs/${jobId}/stop`, { method: "POST" });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "Failed to stop random scan.");
    }
  } catch (err) {
    alert(err.message || "Failed to stop random scan.");
  } finally {
    if (stopRandomScanButton) {
      stopRandomScanButton.textContent = "Stop Random Scan";
      stopRandomScanButton.disabled = false;
    }
  }
}

async function loadApks() {
  const base = getApiBase();
  try {
    const resp = await fetch(`${base}/apks`);
    if (!resp.ok) {
      throw new Error("Failed to fetch apks");
    }
    const apks = await resp.json();
    apksList.innerHTML = renderApks(apks);
    document.querySelectorAll(".use-apk").forEach((button) => {
      button.addEventListener("click", () => {
        setActiveTab("local");
        const path = button.dataset.path;
        const input = localForm.querySelector('input[name="apk_path"]');
        if (input) input.value = path;
      });
    });
    document.querySelectorAll(".scan-apk").forEach((button) => {
      button.addEventListener("click", () => {
        const path = button.dataset.path;
        if (!path) return;
        const payload = {
          ...formToPayload(scanOptionsForm),
          apk_path: path,
          aurora_mode: "local",
        };
        submitScan(payload, null);
      });
    });
  } catch (err) {
    console.error("Failed to load APKs", err);
    apksList.innerHTML = `<p class="hint">Failed to load APKs.</p>`;
  }
}

refreshApksButton.addEventListener("click", loadApks);
if (deepScanPresetButton) {
  deepScanPresetButton.addEventListener("click", () => {
    applyDeepScanPreset();
    appendProgressLog("Deep scan preset enabled.");
  });
}
if (testTopChartsButton) {
  testTopChartsButton.addEventListener("click", () => {
    testTopCharts();
  });
}
saveApiBaseButton.addEventListener("click", () => {
  const value = apiBaseInput.value.trim();
  if (value) {
    setApiBase(value);
    checkApi();
    loadApks();
  }
});

startScanButton.addEventListener("click", (event) => {
  event.preventDefault();
  startScan();
});

if (stopRandomScanButton) {
  stopRandomScanButton.addEventListener("click", (event) => {
    event.preventDefault();
    stopRandomScan();
  });
}

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    setActiveTab(button.dataset.tab);
  });
});

[auroraForm, randomForm, localForm, projectForm, deviceForm].forEach((form) => {
  if (!form) return;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    startScan();
  });
});

if (scanOptionsForm) {
  scanOptionsForm.addEventListener("submit", (event) => {
    event.preventDefault();
  });
}

const activeTab = tabButtons.find((button) => button.classList.contains("active"));
if (activeTab) {
  setActiveTab(activeTab.dataset.tab);
}

checkApi();
loadApks();
setInterval(() => {
  loadApks();
}, 15000);
