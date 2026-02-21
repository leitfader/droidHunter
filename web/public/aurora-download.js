const defaultApi = "http://localhost:8000";
const apiBaseInput = document.getElementById("apiBase");
const apiStatus = document.getElementById("apiStatus");
const saveApiBaseButton = document.getElementById("saveApiBase");
const downloadForm = document.getElementById("downloadForm");
const startDownloadButton = document.getElementById("startDownload");
const downloadResult = document.getElementById("downloadResult");

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
  const formData = new FormData(form);
  const payload = {};
  for (const [key, value] of formData.entries()) {
    if (value === "") continue;
    payload[key] = value;
  }
  return payload;
}

function setResult(message, isError = false) {
  downloadResult.textContent = message;
  downloadResult.style.color = isError ? "var(--danger)" : "var(--muted)";
}

async function startDownload() {
  const base = getApiBase();
  const payload = formToPayload(downloadForm);
  payload.aurora_mode = "anonymous";

  startDownloadButton.disabled = true;
  const originalLabel = startDownloadButton.textContent;
  startDownloadButton.textContent = "Downloading...";
  setResult("Starting download...");

  try {
    const resp = await fetch(`${base}/downloads`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!resp.ok) {
      let detail = "Download failed";
      try {
        const errorData = await resp.json();
        detail = errorData.detail || detail;
      } catch (err) {
        // ignore JSON parse errors
      }
      throw new Error(detail);
    }

    const job = await resp.json();
    const downloadUrl = `${base}/apks/${job.id}/download`;
    downloadResult.style.color = "var(--muted)";
    downloadResult.innerHTML = `Ready: <a class="btn-link" href="${downloadUrl}">Download APK</a>`;
  } catch (err) {
    console.error("Aurora download failed", err);
    setResult(err.message || "Download failed", true);
  } finally {
    startDownloadButton.disabled = false;
    startDownloadButton.textContent = originalLabel;
  }
}

saveApiBaseButton.addEventListener("click", () => {
  const value = apiBaseInput.value.trim();
  if (value) {
    setApiBase(value);
    checkApi();
  }
});

downloadForm.addEventListener("submit", (event) => {
  event.preventDefault();
  startDownload();
});

checkApi();
