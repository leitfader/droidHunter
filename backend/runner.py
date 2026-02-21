import argparse
import json
import subprocess
import sys
import traceback
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from scanner.config import APKS_DIR
from scanner.droidhunter_runner import run_scan


class ProgressTracker:
    def __init__(self, path: Path, total_steps: int) -> None:
        self.path = path
        self.total_steps = max(total_steps, 1)
        self.completed_steps = 0
        self.stage = "starting"
        self.mode = None
        self.status = "running"
        self.current_package = None
        self._write()

    def set_stage(
        self,
        stage: str,
        mode: Optional[str] = None,
        current_package: Optional[str] = None,
    ) -> None:
        self.stage = stage
        if mode is not None:
            self.mode = mode
        if current_package is not None:
            self.current_package = current_package
        self._write()

    def advance(
        self,
        stage: str,
        mode: Optional[str] = None,
        current_package: Optional[str] = None,
    ) -> None:
        self.completed_steps += 1
        self.stage = stage
        if mode is not None:
            self.mode = mode
        if current_package is not None:
            self.current_package = current_package
        self._write()

    def complete(self, status: str) -> None:
        self.status = status
        self.stage = status
        self._write(final=True)

    def _write(self, final: bool = False) -> None:
        percent = int((self.completed_steps / self.total_steps) * 100)
        if final:
            percent = 100
        percent = max(0, min(100, percent))
        payload = {
            "status": self.status,
            "stage": self.stage,
            "mode": self.mode,
            "percent": percent,
            "completed_steps": self.completed_steps,
            "total_steps": self.total_steps,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "current_package": self.current_package,
        }
        try:
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass


def _coerce_float(value: object, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, str) and not value.strip():
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


ROOT_DIR = Path(__file__).resolve().parents[1]
ERROR_LOG_PATH = ROOT_DIR / "error.log"


def _log_error(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        with ERROR_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def _adb_prefix(serial: Optional[str]) -> List[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    return cmd


def _run_adb(args: List[str], serial: Optional[str], timeout: float = 30) -> subprocess.CompletedProcess:
    cmd = _adb_prefix(serial) + args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _list_adb_packages(serial: Optional[str]) -> List[Dict[str, str]]:
    result = _run_adb(["shell", "pm", "list", "packages", "-3", "-f"], serial, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "adb list packages failed")
    packages: List[Dict[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        payload = line[len("package:") :]
        if "=" not in payload:
            continue
        path, name = payload.split("=", 1)
        if path and name:
            packages.append({"package": name.strip(), "path": path.strip()})
    return packages


def _pull_adb_apks(
    serial: Optional[str],
    dest_dir: Path,
    packages: List[Dict[str, str]],
) -> Dict[str, object]:
    downloaded: List[str] = []
    failed: List[Dict[str, str]] = []
    for item in packages:
        package_name = item.get("package") or "unknown"
        remote_path = item.get("path") or ""
        if not remote_path:
            failed.append({"package": package_name, "path": remote_path, "error": "Missing APK path"})
            continue
        dest_path = dest_dir / f"{package_name}.apk"
        result = _run_adb(["pull", remote_path, str(dest_path)], serial, timeout=120)
        if result.returncode == 0 and dest_path.exists():
            downloaded.append(str(dest_path))
        else:
            failed.append(
                {
                    "package": package_name,
                    "path": remote_path,
                    "error": result.stderr.strip() or result.stdout.strip() or "adb pull failed",
                }
            )
    return {"downloaded": downloaded, "failed": failed}


def _prepare_adb_scan(config: Dict[str, object], output_root: Path, tracker: ProgressTracker) -> None:
    serial = config.get("adb_serial")
    dest_dir = Path(str(config.get("apk_dir") or (APKS_DIR / f"{config.get('job_id')}_device")))
    dest_dir.mkdir(parents=True, exist_ok=True)
    tracker.set_stage("pulling_apks")
    packages = _list_adb_packages(serial if isinstance(serial, str) else None)
    result = _pull_adb_apks(serial if isinstance(serial, str) else None, dest_dir, packages)
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "adb_packages.json").write_text(
        json.dumps(
            {
                "serial": serial,
                "packages": packages,
                "downloaded": result.get("downloaded", []),
                "failed": result.get("failed", []),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    downloaded = result.get("downloaded") or []
    if not downloaded:
        raise RuntimeError("ADB scan failed: no APKs could be pulled from the device.")
    config["apk_dir"] = str(dest_dir)
    tracker.set_stage("apk_pull_completed")


def _load_config(path: Path) -> Dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_result(path: Path, data: Dict[str, object]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _run_mode(
    mode: str,
    config: Dict[str, object],
    output_root: Path,
    progress_cb,
) -> Dict[str, object]:
    output_dir = output_root / mode
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_config = {
        "apk_path": config.get("apk_path"),
        "apk_dir": config.get("apk_dir"),
        "aurora_random": bool(config.get("aurora_random", False)),
        "random_count": config.get("random_count"),
        "random_attempts": config.get("random_attempts"),
        "random_terms_file": config.get("random_terms_file"),
        "random_continuous": config.get("random_continuous"),
        "stop_file": config.get("stop_file"),
        "dispenser_url": config.get("dispenser_url"),
        "device_props": config.get("device_props"),
        "locale": config.get("locale"),
        "output_dir": str(output_dir),
        "write_all": bool(config.get("write_enabled", False)),
        "fast_extract": bool(config.get("fast_extract", False)),
        "secrets_scan": bool(config.get("secrets_scan", True)),
        "scan_rate": _coerce_float(config.get("scan_rate"), 1.0),
        "processes": config.get("processes"),
        "timeout_minutes": config.get("timeout_minutes"),
        "use_jadx": bool(config.get("use_jadx", False)),
        "jadx_auto_install": bool(config.get("jadx_auto_install", False)),
        "jadx_timeout_seconds": config.get("jadx_timeout_seconds"),
        "extract_signatures": bool(config.get("extract_signatures", False)),
        "read_config": bool(config.get("read_config", True)),
        "fuzz_collections": bool(config.get("fuzz_collections", False)),
        "fuzz_wordlist": config.get("fuzz_wordlist"),
        "proxy_url": config.get("proxy_url"),
        "resume_auth_file": config.get("resume_auth_file"),
        "resume_path": config.get("resume_path"),
        "project_ids": config.get("project_ids"),
        "project_id_file": config.get("project_id_file"),
        "dns_file": config.get("dns_file"),
        "api_key": config.get("api_key"),
        "app_id": config.get("app_id"),
        "package_name": config.get("package_name"),
    }

    if mode == "auth":
        scan_config["email"] = config.get("auth_email")
        scan_config["password"] = config.get("auth_password")

    scan_result = run_scan(scan_config, progress_cb=progress_cb)

    return {
        "mode": mode,
        "exit_code": scan_result.get("exit_code"),
        "output_dir": str(output_dir),
        "results_dir": scan_result.get("results_dir"),
        "results_candidates": [],
        "summary": scan_result.get("summary", []),
        "files": scan_result.get("files", []),
        "status": scan_result.get("status"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    config = _load_config(config_path)

    output_root = Path(config["output_root"]).resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    log_path = output_root / "runner.log"
    progress_path = output_root / "progress.json"
    result_path = output_root / "result.json"

    runs: List[Dict[str, object]] = []
    final_status = "completed"
    modes = config.get("modes", ["unauth"])
    secrets_scan = bool(config.get("secrets_scan", True))
    steps_per_mode = 4 + (2 if secrets_scan else 0)
    apk_dir = config.get("apk_dir")
    apk_count = 1
    if config.get("aurora_random"):
        try:
            apk_count = max(1, int(float(config.get("random_count") or 5) or 5))
        except Exception:
            apk_count = 1
    elif apk_dir:
        try:
            apk_count = max(1, len(list(Path(str(apk_dir)).glob("*.apk"))))
        except Exception:
            apk_count = 1
    tracker = ProgressTracker(progress_path, total_steps=len(modes) * steps_per_mode * apk_count)
    try:
        with log_path.open("w", encoding="utf-8") as log_file, redirect_stdout(log_file), redirect_stderr(log_file):
            if config.get("adb_scan"):
                _prepare_adb_scan(config, output_root, tracker)
            for mode in modes:
                tracker.set_stage("mode_started", mode=mode)
                def _progress(stage: str, m: str = mode, **meta) -> None:
                    tracker.advance(stage, mode=m, current_package=meta.get("current_package"))

                run_result = _run_mode(
                    mode,
                    config,
                    output_root,
                    progress_cb=_progress,
                )
                runs.append(run_result)
                if run_result.get("status") == "stopped":
                    final_status = "stopped"
                    break
    except Exception as exc:
        _log_error(f"Runner exception for job {config.get('job_id')}: {exc}")
        _log_error(traceback.format_exc())
        tracker.complete("failed")
        _write_result(
            result_path,
            {
                "job_id": config.get("job_id"),
                "status": "failed",
                "error": str(exc),
                "runs": runs,
            },
        )
        return 1

    tracker.complete(final_status)
    _write_result(
        result_path,
        {
            "job_id": config.get("job_id"),
            "status": final_status,
            "runs": runs,
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
