import json
import re
import shutil
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.scanner.aurora import AuroraDownloadError, download_apk, list_top_charts, resolve_package_name
from backend.scanner.config import APKS_DIR, BASE_DIR, DATA_DIR, JOBS_DIR, RESULTS_DIR
from backend.scanner.results_parser import collect_output_files
from backend.scanner.storage import JobStore

APP_VERSION = "0.1.0"

RUNNER_PATH = BASE_DIR / "backend" / "runner.py"
DB_PATH = DATA_DIR / "jobs" / "jobs.db"
ERROR_LOG_PATH = BASE_DIR / "error.log"


class CreateJobRequest(BaseModel):
    package_name: Optional[str] = Field(None, description="Android package name")
    apk_path: Optional[str] = Field(None, description="Local APK path on server")
    apk_dir: Optional[str] = Field(None, description="Directory containing APK files")
    adb_scan: bool = False
    adb_serial: Optional[str] = Field(None, description="ADB device serial")
    aurora_random: bool = False
    random_count: Optional[int] = Field(None, description="Number of random Aurora apps to scan")
    random_attempts: Optional[int] = Field(None, description="Attempts per random selection")
    random_terms_file: Optional[str] = Field(None, description="Wordlist for random search terms")
    random_continuous: bool = False
    random_source: Optional[str] = Field(None, description="Random source: auto, charts, search")
    random_chart: Optional[str] = Field(None, description="Top chart name")
    random_chart_type: Optional[str] = Field(None, description="Top chart type (APPLICATION or GAME)")
    random_chart_limit: Optional[int] = Field(None, description="Top chart package limit")
    random_search_timeout: Optional[float] = Field(None, description="Random search timeout seconds")
    project_id: Optional[str] = Field(None, description="Firebase project ID(s), comma-separated")
    project_id_file: Optional[str] = Field(None, description="File containing Firebase project IDs")
    dns_file: Optional[str] = Field(None, description="DNS file to parse for Firebase project IDs")
    resume_path: Optional[str] = Field(None, description="Resume from previous results directory/file")
    aurora_mode: str = Field("anonymous", description="anonymous or local (aurora accepted as alias)")
    dispenser_url: Optional[str] = None
    device_props: Optional[str] = None
    locale: Optional[str] = None
    auth_enabled: bool = False
    auth_email: Optional[str] = None
    auth_password: Optional[str] = None
    write_enabled: bool = False
    fast_extract: bool = False
    use_jadx: bool = False
    jadx_auto_install: bool = False
    jadx_timeout_minutes: Optional[int] = None
    extract_signatures: bool = False
    secrets_scan: bool = True
    scan_rate: float = 1.0
    read_config: bool = True
    fuzz_collections: bool = False
    fuzz_wordlist: Optional[str] = None
    proxy_url: Optional[str] = None
    resume_auth_file: Optional[str] = None
    api_key: Optional[str] = None
    app_id: Optional[str] = None
    processes: Optional[int] = None
    timeout_minutes: Optional[int] = None
    keep_apk: bool = False


class TopChartsRequest(BaseModel):
    chart: Optional[str] = Field("TOP_SELLING_FREE", description="Top chart name")
    chart_type: Optional[str] = Field("APPLICATION", description="Top chart type")
    chart_limit: Optional[int] = Field(10, description="Number of packages to return")
    dispenser_url: Optional[str] = None
    device_props: Optional[str] = None
    locale: Optional[str] = None


class JobResponse(BaseModel):
    id: str
    created_at: str
    status: str
    package_name: Optional[str]
    apk_path: Optional[str]
    aurora_mode: Optional[str]
    auth_enabled: bool
    write_enabled: bool
    secrets_scan: Optional[bool] = None
    scan_rate: float
    output_root: Optional[str]
    error: Optional[str]
    summary: Dict[str, Any]
    files: List[Dict[str, Any]]
    auth_email: Optional[str]
    progress: Optional[float] = None
    progress_stage: Optional[str] = None
    progress_mode: Optional[str] = None
    progress_status: Optional[str] = None
    progress_item: Optional[str] = None
    keep_apk: Optional[bool] = None
    scan_source: Optional[str] = None


app = FastAPI(title="droidHunter", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = JobStore(DB_PATH)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_error(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        with ERROR_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def _resolve_package_name(query: Optional[str]) -> Optional[str]:
    if not query:
        return query
    try:
        return resolve_package_name(query)
    except AuroraDownloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_request(payload: CreateJobRequest) -> None:
    mode_raw = (payload.aurora_mode or "").strip()
    mode = mode_raw.lower()
    if mode == "aurora":
        mode = "anonymous"
    payload.aurora_mode = mode
    if payload.aurora_random:
        if (
            payload.package_name
            or payload.apk_path
            or payload.apk_dir
            or payload.project_id
            or payload.project_id_file
            or payload.dns_file
            or payload.resume_path
            or payload.adb_scan
        ):
            raise HTTPException(
                status_code=400,
                detail="aurora_random must be used alone without other target inputs.",
            )
    project_mode = bool(
        payload.project_id
        or payload.project_id_file
        or payload.dns_file
        or payload.resume_path
        or payload.apk_dir
        or payload.adb_scan
        or payload.aurora_random
    )
    input_flags = {
        "apk_path": bool(payload.apk_path),
        "apk_dir": bool(payload.apk_dir),
        "adb_scan": bool(payload.adb_scan),
        "aurora_random": bool(payload.aurora_random),
        "project_id": bool(payload.project_id),
        "project_id_file": bool(payload.project_id_file),
        "dns_file": bool(payload.dns_file),
        "resume_path": bool(payload.resume_path),
    }
    if not project_mode:
        input_flags["package_name"] = bool(payload.package_name)
    provided_inputs = [key for key, enabled in input_flags.items() if enabled]
    if not provided_inputs:
        raise HTTPException(
            status_code=400,
            detail="Provide package_name, apk_path, apk_dir, adb_scan, aurora_random, project_id, project_id_file, dns_file, or resume_path.",
        )
    if len(provided_inputs) > 1:
        raise HTTPException(
            status_code=400,
            detail=f"Provide only one input type. Got: {', '.join(provided_inputs)}.",
        )

    if not project_mode:
        if mode not in {"local", "anonymous"}:
            raise HTTPException(
                status_code=400,
                detail="aurora_mode must be local or anonymous (aurora is accepted as an alias).",
            )
        if mode == "local" and not payload.apk_path:
            raise HTTPException(status_code=400, detail="aurora_mode=local requires apk_path.")
        if mode == "anonymous" and not payload.package_name:
            raise HTTPException(
                status_code=400,
                detail="aurora_mode=anonymous requires package_name.",
            )
    if payload.aurora_random and mode == "local":
        raise HTTPException(status_code=400, detail="aurora_random requires aurora_mode=anonymous.")

    if payload.project_id_file:
        path = Path(payload.project_id_file).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail="project_id_file does not exist.")
    if payload.apk_dir:
        path = Path(payload.apk_dir).expanduser()
        if not path.exists() or not path.is_dir():
            raise HTTPException(status_code=400, detail="apk_dir does not exist or is not a directory.")
    if payload.dns_file:
        path = Path(payload.dns_file).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail="dns_file does not exist.")
    if payload.resume_path:
        path = Path(payload.resume_path).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail="resume_path does not exist.")
    if payload.resume_auth_file:
        path = Path(payload.resume_auth_file).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail="resume_auth_file does not exist.")
    if payload.fuzz_wordlist:
        path = Path(payload.fuzz_wordlist).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail="fuzz_wordlist does not exist.")
    if payload.random_terms_file:
        path = Path(payload.random_terms_file).expanduser()
        if not path.exists():
            raise HTTPException(status_code=400, detail="random_terms_file does not exist.")
    if payload.aurora_random:
        if payload.random_count is not None and payload.random_count <= 0:
            raise HTTPException(status_code=400, detail="random_count must be greater than 0.")
        if payload.random_attempts is not None and payload.random_attempts <= 0:
            raise HTTPException(status_code=400, detail="random_attempts must be greater than 0.")
        if payload.random_chart_limit is not None and payload.random_chart_limit <= 0:
            raise HTTPException(status_code=400, detail="random_chart_limit must be greater than 0.")
        if payload.random_search_timeout is not None and payload.random_search_timeout <= 0:
            raise HTTPException(status_code=400, detail="random_search_timeout must be greater than 0.")
    if payload.auth_enabled and (not payload.auth_email or not payload.auth_password):
        raise HTTPException(status_code=400, detail="auth_email and auth_password required for auth_enabled.")


def _prepare_apk(job_id: str, payload: CreateJobRequest) -> Path:
    destination = APKS_DIR / f"{job_id}.apk"
    if payload.apk_path:
        source = Path(payload.apk_path).expanduser().resolve()
        if not source.exists() or not source.is_file():
            raise HTTPException(status_code=400, detail="apk_path does not exist or is not a file.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return destination

    resolved_package = _resolve_package_name(payload.package_name)
    payload.package_name = resolved_package
    try:
        mode = payload.aurora_mode
        return download_apk(
            package_name=resolved_package,
            destination=destination,
            mode=mode,
            dispenser_url=payload.dispenser_url,
            device_props=Path(payload.device_props).expanduser() if payload.device_props else None,
            locale=payload.locale,
        )
    except AuroraDownloadError as exc:
        message = str(exc)
        if "AppNotFound" in message:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Package not found on Google Play: {resolved_package}. "
                    "Check the package name or search by app name."
                ),
            ) from exc
        raise HTTPException(status_code=400, detail=message) from exc


def _cleanup_apk(job_id: str) -> None:
    job = store.get_job(job_id)
    if not job:
        return
    if job.get("keep_apk"):
        return
    apk_path = job.get("apk_path")
    if not apk_path:
        return
    try:
        path = Path(str(apk_path)).resolve()
    except Exception:
        return
    apks_root = APKS_DIR.resolve()
    if path != apks_root and apks_root not in path.parents:
        return
    try:
        if path.exists():
            path.unlink()
        download_dir = APKS_DIR / f"{job_id}_files"
        if download_dir.exists() and download_dir.is_dir():
            shutil.rmtree(download_dir)
    except Exception as exc:
        _log_error(f"Failed to delete APK for job {job_id}: {exc}")
        return
    store.update_job(job_id, apk_path=None)


def _attach_progress(job: Dict[str, Any]) -> Dict[str, Any]:
    output_root = job.get("output_root")
    if not output_root:
        return job
    progress_path = Path(output_root) / "progress.json"
    if not progress_path.exists():
        return job
    try:
        data = json.loads(progress_path.read_text(encoding="utf-8"))
    except Exception:
        return job
    job["progress"] = data.get("percent")
    job["progress_stage"] = data.get("stage")
    job["progress_mode"] = data.get("mode")
    job["progress_status"] = data.get("status")
    job["progress_item"] = data.get("current_package")
    return job


def _stop_job(job_id: str) -> None:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    output_root = job.get("output_root")
    if not output_root:
        raise HTTPException(status_code=400, detail="Job has no output directory.")
    stop_path = Path(str(output_root)) / "stop.txt"
    stop_path.parent.mkdir(parents=True, exist_ok=True)
    stop_path.write_text("stop", encoding="utf-8")


def _delete_job_assets(job: Dict[str, Any]) -> None:
    apk_paths = []
    if job.get("apk_path"):
        apk_paths.append(Path(str(job["apk_path"])))
    apk_paths.append(APKS_DIR / f"{job['id']}.apk")
    for apk_path in apk_paths:
        try:
            if apk_path.exists() and apk_path.is_file():
                apk_path.unlink()
        except Exception as exc:
            _log_error(f"Failed to delete APK for job {job['id']}: {exc}")

    output_root = job.get("output_root")
    if output_root:
        try:
            out_path = Path(str(output_root))
            if out_path.exists() and out_path.is_dir():
                shutil.rmtree(out_path)
        except Exception as exc:
            _log_error(f"Failed to delete results for job {job['id']}: {exc}")

    config_path = JOBS_DIR / f"{job['id']}.json"
    try:
        if config_path.exists():
            config_path.unlink()
    except Exception as exc:
        _log_error(f"Failed to delete config for job {job['id']}: {exc}")


def _write_config(
    job_id: str,
    payload: CreateJobRequest,
    apk_path: Optional[Path],
    output_root: Path,
    *,
    apk_dir_override: Optional[str] = None,
) -> Path:
    deep_scan = bool(payload.aurora_random)
    default_wordlist = BASE_DIR / "OpenFirebase" / "openfirebase" / "wordlist" / "firestore-collections.txt"
    fuzz_wordlist = payload.fuzz_wordlist
    if deep_scan and not fuzz_wordlist and default_wordlist.exists():
        fuzz_wordlist = str(default_wordlist)

    config = {
        "job_id": job_id,
        "apk_path": str(apk_path) if apk_path else None,
        "apk_dir": apk_dir_override if apk_dir_override is not None else payload.apk_dir,
        "output_root": str(output_root),
        "modes": ["unauth", "auth"] if payload.auth_enabled else ["unauth"],
        "write_enabled": payload.write_enabled,
        "fast_extract": False if deep_scan else payload.fast_extract,
        "use_jadx": True if deep_scan else payload.use_jadx,
        "jadx_auto_install": True if deep_scan else payload.jadx_auto_install,
        "jadx_timeout_seconds": (payload.jadx_timeout_minutes or 0) * 60 if payload.jadx_timeout_minutes else None,
        "extract_signatures": True if deep_scan else payload.extract_signatures,
        "secrets_scan": True if deep_scan else payload.secrets_scan,
        "scan_rate": payload.scan_rate,
        "processes": payload.processes,
        "timeout_minutes": payload.timeout_minutes,
        "auth_email": payload.auth_email,
        "auth_password": payload.auth_password,
        "read_config": True if deep_scan else payload.read_config,
        "fuzz_collections": True if deep_scan else payload.fuzz_collections,
        "fuzz_wordlist": fuzz_wordlist,
        "proxy_url": payload.proxy_url,
        "resume_auth_file": payload.resume_auth_file,
        "resume_path": payload.resume_path,
        "aurora_random": payload.aurora_random,
        "adb_scan": payload.adb_scan,
        "adb_serial": payload.adb_serial,
        "random_count": payload.random_count,
        "random_attempts": payload.random_attempts,
        "random_terms_file": payload.random_terms_file,
        "random_continuous": payload.random_continuous,
        "random_source": payload.random_source,
        "random_chart": payload.random_chart,
        "random_chart_type": payload.random_chart_type,
        "random_chart_limit": payload.random_chart_limit,
        "random_search_timeout": payload.random_search_timeout,
        "project_ids": payload.project_id,
        "project_id_file": payload.project_id_file,
        "dns_file": payload.dns_file,
        "api_key": payload.api_key,
        "app_id": payload.app_id,
        "package_name": payload.package_name,
        "dispenser_url": payload.dispenser_url,
        "device_props": payload.device_props,
        "locale": payload.locale,
        "stop_file": str(output_root / "stop.txt"),
    }
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    config_path = JOBS_DIR / f"{job_id}.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def _spawn_runner(job_id: str, config_path: Path, output_root: Path) -> None:
    def _monitor(process: subprocess.Popen) -> None:
        exit_code = process.wait()
        result_path = output_root / "result.json"
        summary: Dict[str, Any] = {}
        files: List[Dict[str, Any]] = []
        error = None
        status = "completed" if exit_code == 0 else "failed"

        if result_path.exists():
            try:
                result_data = json.loads(result_path.read_text(encoding="utf-8"))
                result_status = result_data.get("status")
                if result_status == "failed":
                    status = "failed"
                    error = result_data.get("error")
                elif result_status == "stopped":
                    status = "stopped"

                runs = result_data.get("runs", [])
                for run in runs:
                    mode = run.get("mode")
                    run_summary = run.get("summary") or []
                    summary[mode] = run_summary
                    for file_item in run.get("files", []):
                        files.append(
                            {
                                "mode": mode,
                                "name": file_item.get("name"),
                                "path": file_item.get("path"),
                            }
                        )
            except Exception as exc:
                status = "failed"
                error = f"Failed to parse result.json: {exc}"
                _log_error(f"Job {job_id} failed to parse result.json: {exc}")

        if not files and output_root.exists():
            for mode_dir in output_root.iterdir():
                if mode_dir.is_dir():
                    for file_item in collect_output_files(mode_dir):
                        files.append({"mode": mode_dir.name, "name": file_item["name"], "path": file_item["path"]})

        if status == "failed":
            _log_error(f"Job {job_id} failed: {error or 'Unknown error'}")

        store.update_job(job_id, status=status, error=error, summary=summary, files=files)
        if status in ("completed", "failed"):
            _cleanup_apk(job_id)

    output_root.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [sys.executable, str(RUNNER_PATH), "--config", str(config_path)],
        cwd=str(BASE_DIR),
    )
    thread = threading.Thread(target=_monitor, args=(process,), daemon=True)
    thread.start()


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "version": APP_VERSION}


@app.get("/jobs", response_model=List[JobResponse])
def list_jobs() -> List[Dict[str, Any]]:
    return [_attach_progress(job) for job in store.list_jobs()]


@app.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: str) -> Dict[str, Any]:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _attach_progress(job)


@app.delete("/jobs/{job_id}")
def delete_job(job_id: str) -> Dict[str, Any]:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job_with_progress = _attach_progress(dict(job))
    base_status = job_with_progress.get("status") or "running"
    progress_status = job_with_progress.get("progress_status") or base_status
    effective_status = base_status if base_status in {"failed", "completed", "stopped"} else progress_status
    if effective_status == "running":
        raise HTTPException(status_code=400, detail="Stop the scan before deleting it.")
    _delete_job_assets(job_with_progress)
    store.delete_job(job_id)
    return {"status": "deleted"}


@app.get("/apks")
def list_apks() -> List[Dict[str, Any]]:
    APKS_DIR.mkdir(parents=True, exist_ok=True)
    jobs_by_id = {job["id"]: job for job in store.list_jobs()}
    items: List[Dict[str, Any]] = []
    for path in sorted(APKS_DIR.glob("*.apk"), key=lambda p: p.stat().st_mtime, reverse=True):
        stat = path.stat()
        job = jobs_by_id.get(path.stem, {})
        items.append(
            {
                "name": path.name,
                "path": str(path),
                "job_id": path.stem,
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "package_name": job.get("package_name"),
                "aurora_mode": job.get("aurora_mode"),
            }
        )
    return items


@app.get("/apks/{job_id}/download")
def download_apk_file(job_id: str) -> FileResponse:
    apk_path = APKS_DIR / f"{job_id}.apk"
    if not apk_path.exists() or not apk_path.is_file():
        raise HTTPException(status_code=404, detail="APK not found")
    return FileResponse(str(apk_path), filename=apk_path.name)


@app.post("/downloads", response_model=JobResponse)
def create_download(payload: CreateJobRequest) -> Dict[str, Any]:
    _validate_request(payload)
    if (
        payload.project_id
        or payload.project_id_file
        or payload.dns_file
        or payload.resume_path
        or payload.apk_dir
        or payload.adb_scan
        or payload.aurora_random
    ):
        raise HTTPException(
            status_code=400,
            detail="downloads endpoint only supports package_name or apk_path.",
        )
    job_id = str(uuid.uuid4())

    apk_path = _prepare_apk(job_id, payload)
    job = {
        "id": job_id,
        "created_at": _now_iso(),
        "status": "downloaded",
        "package_name": payload.package_name,
        "apk_path": str(apk_path),
        "aurora_mode": payload.aurora_mode,
        "dispenser_url": payload.dispenser_url,
        "device_props": payload.device_props,
        "locale": payload.locale,
        "keep_apk": bool(payload.keep_apk),
        "scan_source": "aurora" if payload.package_name else "local",
        "auth_enabled": payload.auth_enabled,
        "write_enabled": payload.write_enabled,
        "secrets_scan": payload.secrets_scan,
        "scan_rate": payload.scan_rate,
        "output_root": None,
        "error": None,
        "summary": {},
        "files": [],
        "auth_email": payload.auth_email,
    }
    store.create_job(job)
    return job


@app.post("/jobs", response_model=JobResponse)
def create_job(payload: CreateJobRequest) -> Dict[str, Any]:
    _validate_request(payload)
    if payload.aurora_random:
        for job in store.list_jobs():
            if job.get("scan_source") == "aurora_random" and job.get("status") == "running":
                raise HTTPException(
                    status_code=400,
                    detail="An automated scan is already running. Stop it before starting a new one.",
                )
    job_id = str(uuid.uuid4())
    apk_path = None
    project_mode = (
        payload.project_id
        or payload.project_id_file
        or payload.dns_file
        or payload.resume_path
        or payload.apk_dir
        or payload.adb_scan
        or payload.aurora_random
    )
    device_apk_dir = None
    if payload.adb_scan:
        device_apk_dir = str(APKS_DIR / f"{job_id}_device")
    if not project_mode and (payload.package_name or payload.apk_path):
        apk_path = _prepare_apk(job_id, payload)
    output_root = RESULTS_DIR / job_id
    config_path = _write_config(job_id, payload, apk_path, output_root, apk_dir_override=device_apk_dir)

    if payload.aurora_random:
        scan_source = "aurora_random"
    elif payload.adb_scan:
        scan_source = "device"
    elif payload.apk_dir:
        scan_source = "apk_dir"
    elif payload.project_id or payload.project_id_file or payload.dns_file or payload.resume_path:
        scan_source = "project"
    elif payload.apk_path and not payload.package_name:
        scan_source = "local"
    elif payload.package_name:
        scan_source = "aurora"
    else:
        scan_source = "unknown"

    job = {
        "id": job_id,
        "created_at": _now_iso(),
        "status": "running",
        "package_name": payload.package_name,
        "apk_path": str(apk_path) if apk_path else None,
        "aurora_mode": payload.aurora_mode,
        "dispenser_url": payload.dispenser_url,
        "device_props": payload.device_props,
        "locale": payload.locale,
        "keep_apk": bool(payload.keep_apk),
        "scan_source": scan_source,
        "auth_enabled": payload.auth_enabled,
        "write_enabled": payload.write_enabled,
        "secrets_scan": payload.secrets_scan,
        "scan_rate": payload.scan_rate,
        "output_root": str(output_root),
        "error": None,
        "summary": {},
        "files": [],
        "auth_email": payload.auth_email,
    }
    store.create_job(job)
    _spawn_runner(job_id, config_path, output_root)
    return job


@app.post("/jobs/{job_id}/apk/restore")
def restore_apk(job_id: str) -> Dict[str, Any]:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    store.update_job(job_id, keep_apk=True)
    apk_path = job.get("apk_path")
    if apk_path:
        path = Path(str(apk_path))
        if path.exists():
            return {"status": "exists", "download_url": f"/apks/{job_id}/download"}

    package_name = job.get("package_name")
    if not package_name:
        raise HTTPException(status_code=400, detail="APK is not available for re-download.")
    destination = APKS_DIR / f"{job_id}.apk"
    try:
        download_apk(
            package_name=package_name,
            destination=destination,
            mode=job.get("aurora_mode") or "anonymous",
            dispenser_url=job.get("dispenser_url"),
            device_props=Path(job["device_props"]).expanduser() if job.get("device_props") else None,
            locale=job.get("locale"),
        )
    except AuroraDownloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store.update_job(job_id, apk_path=str(destination), keep_apk=True)
    return {"status": "downloaded", "download_url": f"/apks/{job_id}/download"}


@app.post("/jobs/{job_id}/stop")
def stop_job(job_id: str) -> Dict[str, Any]:
    _stop_job(job_id)
    return {"status": "stopping"}


@app.get("/jobs/{job_id}/files")
def download_file(job_id: str, path: str = Query(..., description="Absolute file path")) -> FileResponse:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    output_root = Path(job["output_root"] or "").resolve()
    file_path = Path(path).expanduser().resolve()
    if not output_root.exists():
        raise HTTPException(status_code=404, detail="Results directory not found")
    if output_root not in file_path.parents:
        raise HTTPException(status_code=403, detail="File outside job results directory")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(str(file_path), filename=file_path.name)


@app.get("/jobs/{job_id}/line")
def get_file_line(
    job_id: str,
    path: str = Query(..., description="Absolute file path"),
    line: int = Query(..., ge=1, description="1-based line number"),
    detector: Optional[str] = Query(None, description="Detector name for match extraction"),
) -> Dict[str, Any]:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    output_root = Path(job["output_root"] or "").resolve()
    file_path = Path(path).expanduser().resolve()
    if not output_root.exists():
        raise HTTPException(status_code=404, detail="Results directory not found")
    if output_root not in file_path.parents:
        raise HTTPException(status_code=403, detail="File outside job results directory")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    content = ""
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, text in enumerate(handle, start=1):
                if index == line:
                    content = text.rstrip("\n")
                    break
                if index > line:
                    break
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read line: {exc}") from exc
    match = _extract_detector_match(detector, content)
    return {"line": content, "match": match}


def _extract_detector_match(detector: Optional[str], content: str) -> Optional[str]:
    if not detector or not content:
        return None
    name = detector.strip().lower()
    if name == "gitlab":
        token_re = re.compile(r"glpat-[0-9A-Za-z_-]{10,}")
    elif name == "box":
        token_re = re.compile(r"(?:box)(?:[0-9A-Za-z]{20,})", re.IGNORECASE)
    elif name == "github":
        token_re = re.compile(r"gh[pousr]_[A-Za-z0-9]{10,}")
    elif name == "slack":
        token_re = re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")
    elif name == "google":
        token_re = re.compile(r"AIza[0-9A-Za-z\\-_]{30,}")
    else:
        return None

    for match in token_re.finditer(content):
        return match.group(0)
    return None


def _load_random_batch_entries(output_root: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not output_root.exists():
        return entries

    for mode_dir in sorted([p for p in output_root.iterdir() if p.is_dir()]):
        results_roots = sorted(
            [p for p in mode_dir.iterdir() if p.is_dir() and p.name.endswith("_results")],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not results_roots:
            results_roots = [mode_dir]

        for results_root in results_roots:
            scan_path = results_root / "scan.json"
            if scan_path.exists():
                try:
                    data = json.loads(scan_path.read_text(encoding="utf-8"))
                    batch = data.get("batch") or []
                    if isinstance(batch, list) and batch:
                        for item in batch:
                            if not isinstance(item, dict):
                                continue
                            results_dir = item.get("results_dir") or ""
                            package_name = item.get("package_name")
                            if not package_name and results_dir:
                                package_name = Path(str(results_dir)).name
                            if not package_name:
                                package_name = results_root.name
                            entries.append(
                                {
                                    "package_name": package_name,
                                    "summary": item.get("summary") or [],
                                    "results_dir": results_dir,
                                    "mode": mode_dir.name,
                                }
                            )
                        continue
                except Exception:
                    pass

            for sub_dir in sorted([p for p in results_root.iterdir() if p.is_dir()]):
                if sub_dir.name == "downloads":
                    continue
                summary_path = sub_dir / "summary.json"
                summary = []
                if summary_path.exists():
                    try:
                        summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    except Exception:
                        summary = []
                entries.append(
                    {
                        "package_name": sub_dir.name,
                        "summary": summary,
                        "results_dir": str(sub_dir),
                        "mode": mode_dir.name,
                    }
                )

    return entries


@app.get("/jobs/{job_id}/batch")
def get_job_batch(job_id: str) -> List[Dict[str, Any]]:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("scan_source") != "aurora_random":
        return []
    output_root = Path(job.get("output_root") or "").resolve()
    if not output_root.exists():
        return []
    return _load_random_batch_entries(output_root)


@app.post("/aurora/top-charts")
def get_top_charts(payload: TopChartsRequest) -> Dict[str, Any]:
    limit = payload.chart_limit or 10
    if limit <= 0:
        raise HTTPException(status_code=400, detail="chart_limit must be greater than 0.")
    try:
        packages = list_top_charts(
            chart=str(payload.chart or "TOP_SELLING_FREE"),
            chart_type=str(payload.chart_type or "APPLICATION"),
            limit=limit,
            dispenser_url=payload.dispenser_url,
            device_props=Path(payload.device_props).expanduser() if payload.device_props else None,
            locale=payload.locale,
        )
    except AuroraDownloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"packages": packages[:limit]}
