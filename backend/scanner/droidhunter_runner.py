import concurrent.futures
import json
import os
import random
import shutil
import socket
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional
from urllib.parse import urlparse

from .aurora import (
    AuroraDownloadError,
    PACKAGE_NAME_RE,
    download_apk,
    list_top_charts,
    resolve_package_name,
)
from .config import DATA_DIR
from .droidhunter_scanner import (
    FirebaseTargets,
    _build_summary,
    _parse_dns_project_ids,
    build_targets_from_project_ids,
    extract_firebase_targets,
    load_targets_from_resume,
    scan_firebase_targets,
)
from .results_parser import collect_output_files

MAX_SECRET_FINDINGS = 200
DEFAULT_RANDOM_TERMS = [
    "chat",
    "music",
    "photo",
    "video",
    "game",
    "travel",
    "fitness",
    "finance",
    "news",
    "shopping",
    "weather",
    "notes",
    "calendar",
    "stream",
    "translate",
    "camera",
    "food",
    "music player",
    "puzzle",
    "radio",
    "health",
    "maps",
    "social",
    "wallet",
    "alarm",
    "clock",
    "recipe",
]

BLACKLIST_PATH = DATA_DIR / "random_blacklist.json"
DEFAULT_DISPENSER_URL = "https://auroraoss.com/api/auth"


def _coerce_float(value: object, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, str) and not value.strip():
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _should_stop(config: Dict[str, object]) -> bool:
    stop_file = config.get("stop_file")
    if not stop_file:
        return False
    try:
        return Path(str(stop_file)).exists()
    except Exception:
        return False


def run_scan(
    config: Dict[str, object],
    progress_cb: Optional[Callable[..., None]] = None,
) -> Dict[str, object]:
    apk_path = Path(str(config["apk_path"])) if config.get("apk_path") else None
    output_dir = Path(str(config["output_dir"]))
    output_dir.mkdir(parents=True, exist_ok=True)

    results_dir = output_dir / f"{_timestamp()}_results"
    results_dir.mkdir(parents=True, exist_ok=True)

    if _should_stop(config):
        return {
            "exit_code": 0,
            "results_dir": str(results_dir),
            "summary": [],
            "files": [],
            "status": "stopped",
        }

    if config.get("aurora_random"):
        return _run_random_aurora_scan(config, results_dir, progress_cb)

    apk_dir = config.get("apk_dir")
    if apk_dir:
        return _run_apk_dir_scan(Path(str(apk_dir)), config, results_dir, progress_cb)

    if progress_cb:
        progress_cb("extracting_targets")
    targets = None
    resume_path = config.get("resume_path")
    if resume_path:
        targets = load_targets_from_resume(Path(str(resume_path)))
    else:
        project_ids = set()
        raw_project_ids = config.get("project_ids")
        if raw_project_ids:
            if isinstance(raw_project_ids, str):
                project_ids.update([p.strip() for p in raw_project_ids.split(",") if p.strip()])
            elif isinstance(raw_project_ids, (list, tuple, set)):
                project_ids.update([str(p).strip() for p in raw_project_ids if str(p).strip()])
        project_id_file = config.get("project_id_file")
        if project_id_file:
            try:
                content = Path(str(project_id_file)).read_text(encoding="utf-8", errors="ignore")
                project_ids.update([line.strip() for line in content.splitlines() if line.strip()])
            except Exception:
                pass
        dns_file = config.get("dns_file")
        if dns_file:
            try:
                project_ids.update(_parse_dns_project_ids(Path(str(dns_file))))
            except Exception:
                pass

        if project_ids:
            targets = build_targets_from_project_ids(
                project_ids,
                api_key=config.get("api_key"),
                app_id=config.get("app_id"),
                package_name=config.get("package_name"),
            )

    if targets is None:
        if not apk_path:
            raise ValueError("apk_path is required for APK-based scans.")
        jadx_timeout_seconds = _coerce_float(config.get("jadx_timeout_seconds"), 0)
        targets = extract_firebase_targets(
            apk_path,
            fast_extract=bool(config.get("fast_extract", False)),
            use_jadx=bool(config.get("use_jadx", False)),
            jadx_auto_install=bool(config.get("jadx_auto_install", False)),
            jadx_timeout_seconds=int(jadx_timeout_seconds) or None,
            extract_signatures=bool(config.get("extract_signatures", False)),
        )
    if progress_cb:
        progress_cb("targets_extracted")
    if _should_stop(config):
        files = collect_output_files(results_dir)
        return {
            "exit_code": 0,
            "results_dir": str(results_dir),
            "summary": [],
            "files": files,
            "status": "stopped",
        }
    timeout_minutes = _coerce_float(config.get("timeout_minutes"), 0)
    timeout_seconds = timeout_minutes * 60 if timeout_minutes > 0 else 15.0

    if progress_cb:
        progress_cb("scanning_firebase")
    scan_results = scan_firebase_targets(
        targets=targets,
        write_enabled=bool(config.get("write_all", False)),
        scan_rate=_coerce_float(config.get("scan_rate"), 1.0),
        timeout_seconds=timeout_seconds,
        auth_email=config.get("email"),
        auth_password=config.get("password"),
        output_dir=results_dir,
        read_config=bool(config.get("read_config", True)),
        fuzz_collections=bool(config.get("fuzz_collections", False)),
        fuzz_wordlist=Path(str(config.get("fuzz_wordlist"))) if config.get("fuzz_wordlist") else None,
        proxy=config.get("proxy_url"),
        resume_auth_file=Path(str(config.get("resume_auth_file"))) if config.get("resume_auth_file") else None,
        manual_api_key=config.get("api_key"),
        manual_app_id=config.get("app_id"),
    )
    if progress_cb:
        progress_cb("firebase_scan_completed")
    if _should_stop(config):
        files = collect_output_files(results_dir)
        return {
            "exit_code": 0,
            "results_dir": str(results_dir),
            "summary": scan_results.get("summary", []),
            "files": files,
            "status": "stopped",
        }

    if bool(config.get("secrets_scan", True)) and apk_path:
        if progress_cb:
            progress_cb("scanning_secrets")
        secrets = _run_trufflehog(apk_path, results_dir, timeout_seconds=timeout_seconds)
        scan_results["secrets"] = secrets
        scan_results.setdefault("summary", []).append(
            {
                "title": "Secrets",
                "counts": {
                    "Findings": secrets.get("count", 0),
                    "Verified": secrets.get("verified", 0),
                    "Errors": 1 if secrets.get("error") else 0,
                },
            }
        )
        if progress_cb:
            progress_cb("secrets_scan_completed")

    (results_dir / "targets.json").write_text(
        json.dumps(scan_results.get("targets", {}), indent=2), encoding="utf-8"
    )
    (results_dir / "scan.json").write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
    (results_dir / "summary.json").write_text(
        json.dumps(scan_results.get("summary", []), indent=2), encoding="utf-8"
    )

    files = collect_output_files(results_dir)
    return {
        "exit_code": 0,
        "results_dir": str(results_dir),
        "summary": scan_results.get("summary", []),
        "files": files,
    }


def _merge_targets(dest: FirebaseTargets, src: FirebaseTargets) -> None:
    dest.project_ids.update(src.project_ids)
    dest.api_keys.update(src.api_keys)
    dest.app_ids.update(src.app_ids)
    dest.database_urls.update(src.database_urls)
    dest.storage_buckets.update(src.storage_buckets)
    dest.firestore_collections.update(src.firestore_collections)
    for name in src.package_names:
        dest.add_package_name(name)
    for cert in src.cert_sha1_list:
        dest.add_cert_sha1(cert)
    for item in src.items:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            dest.record_item(item[0], item[1])
    for key, details in src.api_key_details.items():
        dest_details = dest.api_key_details.setdefault(
            key, {"kinds": set(), "sources": set(), "resources": set(), "detectors": set()}
        )
        for field in ("kinds", "sources", "resources", "detectors"):
            dest_details[field].update(details.get(field, set()))


def _load_random_terms(path: Optional[Path]) -> list[str]:
    if path and path.exists():
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            terms = [line.strip() for line in content.splitlines() if line.strip()]
            if terms:
                return terms
        except Exception:
            pass
    return list(DEFAULT_RANDOM_TERMS)


def _load_blacklist() -> set[str]:
    if not BLACKLIST_PATH.exists():
        return set()
    try:
        content = json.loads(BLACKLIST_PATH.read_text(encoding="utf-8"))
    except Exception:
        return set()
    if isinstance(content, list):
        return {str(item) for item in content if str(item).strip()}
    return set()


def _save_blacklist(entries: set[str]) -> None:
    try:
        BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        BLACKLIST_PATH.write_text(
            json.dumps(sorted(entries), indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def _pick_random_query(terms: list[str]) -> str:
    term = random.choice(terms) if terms else random.choice(DEFAULT_RANDOM_TERMS)
    return str(term).strip()


def _resolve_package_with_timeout(query: str, timeout_seconds: float) -> str:
    if timeout_seconds <= 0:
        return resolve_package_name(query)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(resolve_package_name, query)
        try:
            return future.result(timeout=timeout_seconds)
        except concurrent.futures.TimeoutError as exc:
            raise AuroraDownloadError(
                f"Search timeout after {int(timeout_seconds)}s"
            ) from exc


def _resolve_host(host: str) -> bool:
    if not host:
        return False
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def _preflight_random_scan(
    config: Dict[str, object],
    progress_cb: Optional[Callable[..., None]],
) -> None:
    if progress_cb:
        progress_cb("preflight_check", current_package="")
    dispenser_url = str(config.get("dispenser_url") or DEFAULT_DISPENSER_URL)
    dispenser_host = urlparse(dispenser_url).hostname or dispenser_url
    failures = []
    if not _resolve_host("play.google.com"):
        failures.append("play.google.com")
    if not _resolve_host(dispenser_host):
        failures.append(dispenser_host)
    if failures:
        raise RuntimeError(
            "Random scan preflight failed: unable to resolve "
            + ", ".join(sorted(set(failures)))
            + ". Check DNS/network or set a custom dispenser URL."
        )


def _load_top_chart_pool(
    config: Dict[str, object],
    progress_cb: Optional[Callable[..., None]],
    blacklist: set[str],
) -> list[str]:
    if progress_cb:
        progress_cb("loading_top_charts", current_package="")
    chart = str(
        config.get("random_chart")
        or os.environ.get("AURORA_RANDOM_CHART")
        or "TOP_SELLING_FREE"
    )
    chart_type = str(
        config.get("random_chart_type")
        or os.environ.get("AURORA_RANDOM_CHART_TYPE")
        or "APPLICATION"
    )
    limit_raw = (
        config.get("random_chart_limit")
        or os.environ.get("AURORA_RANDOM_CHART_LIMIT")
        or 200
    )
    try:
        limit = max(1, int(float(limit_raw)))
    except Exception:
        limit = 200
    try:
        pool = list_top_charts(
            chart=chart,
            chart_type=chart_type,
            limit=limit,
            dispenser_url=str(config.get("dispenser_url") or "") or None,
            device_props=Path(str(config.get("device_props"))).expanduser()
            if config.get("device_props")
            else None,
            locale=str(config.get("locale") or "") or None,
        )
    except AuroraDownloadError:
        if progress_cb:
            progress_cb("top_charts_failed", current_package="")
        return []
    cleaned: list[str] = []
    for pkg in pool:
        name = str(pkg).strip()
        if not name or name in blacklist:
            continue
        if not PACKAGE_NAME_RE.match(name):
            continue
        cleaned.append(name)
    pool = cleaned
    random.shuffle(pool)
    if progress_cb:
        progress_cb(f"top_charts_loaded ({len(pool)})", current_package="")
    return pool


def _cleanup_downloaded_apk(apk_path: Path) -> None:
    try:
        if apk_path.exists():
            apk_path.unlink()
        output_dir = apk_path.parent / f"{apk_path.stem}_files"
        if output_dir.exists() and output_dir.is_dir():
            shutil.rmtree(output_dir)
    except Exception:
        pass


def _run_random_aurora_scan(
    config: Dict[str, object],
    results_dir: Path,
    progress_cb: Optional[Callable[..., None]],
) -> Dict[str, object]:
    count = int(float(config.get("random_count") or 5) or 5)
    attempts = int(float(config.get("random_attempts") or 5) or 5)
    continuous = bool(config.get("random_continuous", False))
    if continuous:
        count = max(count, 1)
    terms_path = Path(str(config.get("random_terms_file"))) if config.get("random_terms_file") else None
    terms = _load_random_terms(terms_path)
    seen_packages: set[str] = set()
    blacklist = _load_blacklist()

    stop_file = None
    if config.get("stop_file"):
        stop_file = Path(str(config.get("stop_file")))

    downloads_dir = results_dir / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)

    combined_targets = FirebaseTargets()
    combined_services = {
        "rtdb": {"checks": []},
        "firestore": {"checks": [], "write_checks": []},
        "storage": {"checks": []},
        "remote_config": {"checks": []},
    }
    batch_results = []
    failures = []

    timeout_minutes = _coerce_float(config.get("timeout_minutes"), 0)
    timeout_seconds = timeout_minutes * 60 if timeout_minutes > 0 else 15.0

    search_timeout = _coerce_float(
        config.get("random_search_timeout"),
        _coerce_float(os.environ.get("AURORA_RANDOM_SEARCH_TIMEOUT_SECONDS"), 12.0),
    )

    _preflight_random_scan(config, progress_cb)

    random_source = str(
        config.get("random_source")
        or os.environ.get("AURORA_RANDOM_SOURCE")
        or "auto"
    ).strip().lower()
    chart_pool: list[str] = []
    if random_source in {"charts", "top_charts", "auto"}:
        chart_pool = _load_top_chart_pool(config, progress_cb, blacklist)

    scanned = 0
    while True:
        if stop_file and stop_file.exists():
            break
        if not continuous and scanned >= count:
            break
        package_name = None
        last_error = None
        if random_source in {"charts", "top_charts", "auto"}:
            if not chart_pool:
                chart_pool = _load_top_chart_pool(config, progress_cb, blacklist)
            if chart_pool:
                if progress_cb:
                    progress_cb("selecting_from_top_charts", current_package="")
                while chart_pool:
                    candidate = chart_pool.pop()
                    if not candidate:
                        continue
                    if candidate in seen_packages or candidate in blacklist:
                        continue
                    if not PACKAGE_NAME_RE.match(candidate):
                        continue
                    package_name = candidate
                    seen_packages.add(candidate)
                    break
            if not package_name and random_source in {"charts", "top_charts"}:
                if progress_cb:
                    progress_cb("top_charts_empty", current_package="")
                time.sleep(3)
                continue
        if not package_name and random_source in {"auto", "search"}:
            for attempt in range(1, attempts + 1):
                if progress_cb:
                    progress_cb(f"searching_play_store (attempt {attempt}/{attempts})", current_package="")
                query = _pick_random_query(terms)
                try:
                    candidate = _resolve_package_with_timeout(query, search_timeout)
                except AuroraDownloadError as exc:
                    last_error = str(exc)
                    if progress_cb:
                        progress_cb(f"search_failed (attempt {attempt}/{attempts})", current_package="")
                    continue
                if not PACKAGE_NAME_RE.match(candidate):
                    last_error = "Invalid package from search"
                    continue
                if candidate in seen_packages or candidate in blacklist:
                    last_error = "Duplicate package"
                    continue
                package_name = candidate
                seen_packages.add(candidate)
                break

        if not package_name:
            failures.append(
                {
                    "index": scanned + len(failures) + 1,
                    "error": last_error or "No package found",
                }
            )
            continue

        apk_path = downloads_dir / f"{package_name}.apk"
        try:
            if progress_cb:
                progress_cb("downloading_apk", current_package=package_name)
            download_apk(
                package_name=package_name,
                destination=apk_path,
                mode="anonymous",
                dispenser_url=config.get("dispenser_url"),
                device_props=Path(str(config.get("device_props"))).expanduser()
                if config.get("device_props")
                else None,
                locale=config.get("locale"),
            )
        except AuroraDownloadError as exc:
            failures.append(
                {
                    "index": scanned + len(failures) + 1,
                    "package": package_name,
                    "error": str(exc),
                }
            )
            _cleanup_downloaded_apk(apk_path)
            continue

        if progress_cb:
            progress_cb("extracting_targets", current_package=package_name)
        sub_dir = results_dir / package_name
        sub_dir.mkdir(parents=True, exist_ok=True)

        jadx_timeout_seconds = _coerce_float(config.get("jadx_timeout_seconds"), 0)
        targets = extract_firebase_targets(
            apk_path,
            fast_extract=bool(config.get("fast_extract", False)),
            use_jadx=bool(config.get("use_jadx", False)),
            jadx_auto_install=bool(config.get("jadx_auto_install", False)),
            jadx_timeout_seconds=int(jadx_timeout_seconds) or None,
            extract_signatures=bool(config.get("extract_signatures", False)),
        )
        _merge_targets(combined_targets, targets)
        if progress_cb:
            progress_cb("targets_extracted", current_package=package_name)

        if progress_cb:
            progress_cb("scanning_firebase", current_package=package_name)
        scan_results = scan_firebase_targets(
            targets=targets,
            write_enabled=bool(config.get("write_all", False)),
            scan_rate=_coerce_float(config.get("scan_rate"), 1.0),
            timeout_seconds=timeout_seconds,
            auth_email=config.get("email"),
            auth_password=config.get("password"),
            output_dir=sub_dir,
            read_config=bool(config.get("read_config", True)),
            fuzz_collections=bool(config.get("fuzz_collections", False)),
            fuzz_wordlist=Path(str(config.get("fuzz_wordlist"))) if config.get("fuzz_wordlist") else None,
            proxy=config.get("proxy_url"),
            resume_auth_file=Path(str(config.get("resume_auth_file"))) if config.get("resume_auth_file") else None,
            manual_api_key=config.get("api_key"),
            manual_app_id=config.get("app_id"),
        )
        if progress_cb:
            progress_cb("firebase_scan_completed", current_package=package_name)

        if bool(config.get("secrets_scan", True)):
            if progress_cb:
                progress_cb("scanning_secrets", current_package=package_name)
            secrets = _run_trufflehog(apk_path, sub_dir, timeout_seconds=timeout_seconds)
            scan_results["secrets"] = secrets
            scan_results.setdefault("summary", []).append(
                {
                    "title": "Secrets",
                    "counts": {
                        "Findings": secrets.get("count", 0),
                        "Verified": secrets.get("verified", 0),
                        "Errors": 1 if secrets.get("error") else 0,
                    },
                }
            )
            if progress_cb:
                progress_cb("secrets_scan_completed", current_package=package_name)

        (sub_dir / "targets.json").write_text(
            json.dumps(scan_results.get("targets", {}), indent=2), encoding="utf-8"
        )
        (sub_dir / "scan.json").write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
        (sub_dir / "summary.json").write_text(
            json.dumps(scan_results.get("summary", []), indent=2), encoding="utf-8"
        )

        for service_name, service_data in (scan_results.get("services") or {}).items():
            if service_name not in combined_services:
                combined_services[service_name] = {"checks": []}
            combined_services[service_name].setdefault("checks", [])
            combined_services[service_name]["checks"].extend(service_data.get("checks", []))
            if "write_checks" in service_data:
                combined_services[service_name].setdefault("write_checks", [])
                combined_services[service_name]["write_checks"].extend(service_data.get("write_checks", []))

        batch_results.append(
            {
                "package_name": package_name,
                "results_dir": str(sub_dir),
                "summary": scan_results.get("summary", []),
            }
        )

        blacklist.add(package_name)
        _save_blacklist(blacklist)
        _cleanup_downloaded_apk(apk_path)
        scanned += 1

    combined_results = {
        "targets": combined_targets.to_dict(),
        "services": combined_services,
        "batch": batch_results,
        "random_failures": failures,
        "auth": {"enabled": bool(config.get("email") and config.get("password"))},
    }
    combined_results["status"] = "stopped" if stop_file and stop_file.exists() else "completed"
    combined_results["summary"] = _build_summary(combined_results)

    (results_dir / "targets.json").write_text(
        json.dumps(combined_results.get("targets", {}), indent=2), encoding="utf-8"
    )
    (results_dir / "scan.json").write_text(json.dumps(combined_results, indent=2), encoding="utf-8")
    (results_dir / "summary.json").write_text(
        json.dumps(combined_results.get("summary", []), indent=2), encoding="utf-8"
    )

    files = collect_output_files(results_dir)
    return {
        "exit_code": 0,
        "results_dir": str(results_dir),
        "summary": combined_results.get("summary", []),
        "files": files,
        "status": combined_results.get("status"),
    }


def _run_apk_dir_scan(
    apk_dir: Path,
    config: Dict[str, object],
    results_dir: Path,
    progress_cb: Optional[Callable[..., None]],
) -> Dict[str, object]:
    apk_paths = sorted([p for p in apk_dir.glob("*.apk") if p.is_file()])
    if not apk_paths:
        raise ValueError("apk_dir does not contain any .apk files.")

    combined_targets = FirebaseTargets()
    combined_services = {
        "rtdb": {"checks": []},
        "firestore": {"checks": [], "write_checks": []},
        "storage": {"checks": []},
        "remote_config": {"checks": []},
    }
    batch_results = []
    stopped = False

    timeout_minutes = _coerce_float(config.get("timeout_minutes"), 0)
    timeout_seconds = timeout_minutes * 60 if timeout_minutes > 0 else 15.0

    for apk_path in apk_paths:
        if _should_stop(config):
            stopped = True
            break
        if progress_cb:
            progress_cb("extracting_targets")
        sub_dir = results_dir / apk_path.stem
        sub_dir.mkdir(parents=True, exist_ok=True)

        jadx_timeout_seconds = _coerce_float(config.get("jadx_timeout_seconds"), 0)
        targets = extract_firebase_targets(
            apk_path,
            fast_extract=bool(config.get("fast_extract", False)),
            use_jadx=bool(config.get("use_jadx", False)),
            jadx_auto_install=bool(config.get("jadx_auto_install", False)),
            jadx_timeout_seconds=int(jadx_timeout_seconds) or None,
            extract_signatures=bool(config.get("extract_signatures", False)),
        )
        _merge_targets(combined_targets, targets)
        if progress_cb:
            progress_cb("targets_extracted")
        if _should_stop(config):
            stopped = True
            break

        if progress_cb:
            progress_cb("scanning_firebase")
        scan_results = scan_firebase_targets(
            targets=targets,
            write_enabled=bool(config.get("write_all", False)),
            scan_rate=_coerce_float(config.get("scan_rate"), 1.0),
            timeout_seconds=timeout_seconds,
            auth_email=config.get("email"),
            auth_password=config.get("password"),
            output_dir=sub_dir,
            read_config=bool(config.get("read_config", True)),
            fuzz_collections=bool(config.get("fuzz_collections", False)),
            fuzz_wordlist=Path(str(config.get("fuzz_wordlist"))) if config.get("fuzz_wordlist") else None,
            proxy=config.get("proxy_url"),
            resume_auth_file=Path(str(config.get("resume_auth_file"))) if config.get("resume_auth_file") else None,
            manual_api_key=config.get("api_key"),
            manual_app_id=config.get("app_id"),
        )
        if progress_cb:
            progress_cb("firebase_scan_completed")
        if _should_stop(config):
            stopped = True
            break

        if bool(config.get("secrets_scan", True)):
            if progress_cb:
                progress_cb("scanning_secrets")
            secrets = _run_trufflehog(apk_path, sub_dir, timeout_seconds=timeout_seconds)
            scan_results["secrets"] = secrets
            scan_results.setdefault("summary", []).append(
                {
                    "title": "Secrets",
                    "counts": {
                        "Findings": secrets.get("count", 0),
                        "Verified": secrets.get("verified", 0),
                        "Errors": 1 if secrets.get("error") else 0,
                    },
                }
            )
            if progress_cb:
                progress_cb("secrets_scan_completed")
        if _should_stop(config):
            stopped = True
            break

        (sub_dir / "targets.json").write_text(
            json.dumps(scan_results.get("targets", {}), indent=2), encoding="utf-8"
        )
        (sub_dir / "scan.json").write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
        (sub_dir / "summary.json").write_text(
            json.dumps(scan_results.get("summary", []), indent=2), encoding="utf-8"
        )

        for service_name, service_data in (scan_results.get("services") or {}).items():
            if service_name not in combined_services:
                combined_services[service_name] = {"checks": []}
            combined_services[service_name].setdefault("checks", [])
            combined_services[service_name]["checks"].extend(service_data.get("checks", []))
            if "write_checks" in service_data:
                combined_services[service_name].setdefault("write_checks", [])
                combined_services[service_name]["write_checks"].extend(service_data.get("write_checks", []))

        batch_results.append(
            {
                "apk_path": str(apk_path),
                "results_dir": str(sub_dir),
                "summary": scan_results.get("summary", []),
            }
        )

    combined_results = {
        "targets": combined_targets.to_dict(),
        "services": combined_services,
        "batch": batch_results,
        "auth": {"enabled": bool(config.get("email") and config.get("password"))},
    }
    combined_results["status"] = "stopped" if stopped else "completed"
    combined_results["summary"] = _build_summary(combined_results)

    (results_dir / "targets.json").write_text(
        json.dumps(combined_results.get("targets", {}), indent=2), encoding="utf-8"
    )
    (results_dir / "scan.json").write_text(json.dumps(combined_results, indent=2), encoding="utf-8")
    (results_dir / "summary.json").write_text(
        json.dumps(combined_results.get("summary", []), indent=2), encoding="utf-8"
    )

    files = collect_output_files(results_dir)
    return {
        "exit_code": 0,
        "results_dir": str(results_dir),
        "summary": combined_results.get("summary", []),
        "files": files,
        "status": combined_results.get("status"),
    }


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")


def _run_trufflehog(apk_path: Path, results_dir: Path, timeout_seconds: float) -> Dict[str, object]:
    extract_dir = results_dir / "apk_extracted"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(apk_path) as archive:
            archive.extractall(extract_dir)
    except Exception as exc:
        return {
            "enabled": True,
            "count": 0,
            "verified": 0,
            "findings": [],
            "truncated": False,
            "error": f"Failed to extract APK for TruffleHog: {exc}",
        }

    cmd = ["trufflehog", "filesystem", "--json", str(extract_dir)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except FileNotFoundError:
        return {
            "enabled": True,
            "count": 0,
            "verified": 0,
            "findings": [],
            "truncated": False,
            "error": "trufflehog is not installed or not in PATH.",
        }
    except subprocess.TimeoutExpired:
        return {
            "enabled": True,
            "count": 0,
            "verified": 0,
            "findings": [],
            "truncated": False,
            "error": "trufflehog timed out.",
        }

    findings = []
    verified_count = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        finding = _sanitize_trufflehog_record(record, extract_dir)
        if not finding:
            continue
        if finding.get("verified"):
            verified_count += 1
        findings.append(finding)

    error = None
    if proc.returncode not in (0, 1):
        error = proc.stderr.strip() or "trufflehog exited with an error."

    all_findings = findings
    truncated = len(all_findings) > MAX_SECRET_FINDINGS
    limited_findings = all_findings[:MAX_SECRET_FINDINGS]

    (results_dir / "trufflehog.json").write_text(
        json.dumps(all_findings, indent=2), encoding="utf-8"
    )

    return {
        "enabled": True,
        "count": len(all_findings),
        "verified": verified_count,
        "findings": limited_findings,
        "truncated": truncated,
        "error": error,
    }


def _sanitize_trufflehog_record(record: Dict[str, object], base_dir: Path) -> Dict[str, object]:
    detector = record.get("DetectorName") or record.get("DetectorType")
    if not detector:
        return {}
    raw_value = record.get("Raw")
    redacted = record.get("Redacted") or _redact_value(raw_value)
    match_value = _extract_match_value(record, base_dir, fallback=redacted)
    severity = record.get("Severity") or record.get("severity") or "unknown"
    verified = bool(record.get("Verified"))
    file_path, line = _extract_source_location(record)

    return {
        "detector": detector,
        "type": record.get("DetectorType"),
        "redacted": redacted,
        "match": match_value,
        "severity": severity,
        "verified": verified,
        "file": file_path,
        "line": line,
    }


def _extract_source_location(record: Dict[str, object]) -> tuple[str, object]:
    source = record.get("SourceMetadata") or {}
    data = source.get("Data") if isinstance(source, dict) else {}
    if isinstance(data, dict):
        for key in ("Filesystem", "Git", "GCS", "S3"):
            section = data.get(key)
            if isinstance(section, dict):
                file_path = section.get("file") or section.get("path") or "-"
                line = section.get("line") or section.get("line_number")
                return file_path, line
    return "-", record.get("Line")


def _extract_match_value(record: Dict[str, object], base_dir: Path, fallback: str) -> str:
    raw_value = record.get("Raw")
    if raw_value is not None:
        return str(raw_value)
    file_path, line = _extract_source_location(record)
    line_text = _read_line_from_file(file_path, line, base_dir)
    if line_text is not None:
        return line_text
    redacted = record.get("Redacted")
    if redacted:
        return str(redacted)
    return fallback


def _read_line_from_file(file_path: object, line: object, base_dir: Path) -> Optional[str]:
    if not file_path or file_path == "-":
        return None
    try:
        line_number = int(line)
    except (TypeError, ValueError):
        return None
    if line_number <= 0:
        return None
    try:
        candidate = Path(str(file_path))
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        candidate = candidate.resolve()
        base_resolved = base_dir.resolve()
        if base_resolved not in candidate.parents and candidate != base_resolved:
            return None
        if not candidate.exists() or not candidate.is_file():
            return None
        with candidate.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, text in enumerate(handle, start=1):
                if index == line_number:
                    return text.rstrip("\n")
                if index > line_number:
                    break
    except Exception:
        return None
    return None


def _redact_value(value: object) -> str:
    if not value:
        return "-"
    raw = str(value)
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"
