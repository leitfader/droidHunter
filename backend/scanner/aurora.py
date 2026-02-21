import html as html_lib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, urlparse
from urllib.request import Request, urlopen

from .config import BASE_DIR


AURORA_DOWNLOADER_PATH = (
    BASE_DIR
    / "aurora-downloader"
    / "build"
    / "install"
    / "aurora-downloader"
    / "bin"
    / "aurora-downloader"
)


class AuroraDownloadError(RuntimeError):
    pass


PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$")
PLAY_SEARCH_URLS = [
    "https://play.google.com/store/search?c=apps&hl=en&gl=US&q={query}",
    "https://play.google.com/store/search?c=apps&q={query}",
]
PLAY_SUGGEST_URLS = [
    "https://play.google.com/store/search/suggest?c=apps&hl=en&gl=US&q={query}",
    "https://play.google.com/store/search/suggest?c=apps&q={query}",
]
PACKAGE_CANDIDATE_PATTERNS = [
    re.compile(r"/store/apps/details\\?id=([A-Za-z0-9._-]+)"),
    re.compile(r"/store/apps/details\?id=([A-Za-z0-9._-]+)"),
    re.compile(r"details\\?id=([A-Za-z0-9._-]+)"),
    re.compile(r"details\?id=([A-Za-z0-9._-]+)"),
    re.compile(r"data-docid=\"([A-Za-z0-9._-]+)\""),
    re.compile(r"data-docid=\"?([A-Za-z0-9._-]+)\"?"),
    re.compile(r"data-docid=['\"]([A-Za-z0-9._-]+)['\"]"),
    re.compile(r"\"docid\":\"([A-Za-z0-9._-]+)\""),
    re.compile(r"\"appId\":\"([A-Za-z0-9._-]+)\""),
    re.compile(r"\"packageName\":\"([A-Za-z0-9._-]+)\""),
    re.compile(r"id=([A-Za-z0-9._-]+)"),
]
PLAY_URL_HOSTS = {"play.google.com", "market.android.com"}
NON_PACKAGE_TOKENS = {
    "play.google.com",
    "market.android.com",
    "google.com",
    "googleusercontent.com",
    "gstatic.com",
    "googleapis.com",
}


def _normalize_play_text(text: str) -> str:
    if not text:
        return text
    normalized = text.replace("\\u003d", "=").replace("\\u003f", "?").replace("\\u0026", "&")
    return html_lib.unescape(normalized)


def _extract_package_candidates(html: str) -> list[str]:
    if not html:
        return []
    normalized = _normalize_play_text(html)
    seen = set()
    results: list[str] = []
    for pattern in PACKAGE_CANDIDATE_PATTERNS:
        for match in pattern.findall(normalized):
            if not match:
                continue
            candidate = match.strip()
            if not PACKAGE_NAME_RE.match(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            results.append(candidate)
    return results


def _extract_fuzzy_packages(text: str) -> list[str]:
    if not text:
        return []
    normalized = _normalize_play_text(text)
    tokens = re.findall(r"(?:[A-Za-z0-9_]+\\.)+[A-Za-z0-9_]+", normalized)
    results: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        candidate = token.strip()
        if not PACKAGE_NAME_RE.match(candidate):
            continue
        if candidate.lower() in NON_PACKAGE_TOKENS:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        results.append(candidate)
    return results


def _strip_xssi_prefix(text: str) -> str:
    if not text:
        return text
    stripped = text.lstrip()
    if stripped.startswith(")]}'"):
        return stripped.split("\n", 1)[-1]
    return text


def _extract_packages_from_json(payload: object) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()

    def _walk(value: object) -> None:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate and PACKAGE_NAME_RE.match(candidate) and candidate not in seen:
                seen.add(candidate)
                results.append(candidate)
            return
        if isinstance(value, dict):
            for item in value.values():
                _walk(item)
            return
        if isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(payload)
    return results


def _fetch_url(url: str, timeout: int = 10) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    with urlopen(request, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def _extract_package_from_url(text: str) -> Optional[str]:
    if not text:
        return None
    trimmed = text.strip()
    if not trimmed:
        return None
    if trimmed.startswith("market://"):
        parsed = urlparse(trimmed)
        params = parse_qs(parsed.query)
        package = (params.get("id") or [""])[0]
        if package and PACKAGE_NAME_RE.match(package):
            return package
        return None

    if "://" in trimmed:
        try:
            parsed = urlparse(trimmed)
        except Exception:
            return None
        host = (parsed.hostname or "").lower()
        if host in PLAY_URL_HOSTS:
            params = parse_qs(parsed.query)
            package = (params.get("id") or [""])[0]
            if package and PACKAGE_NAME_RE.match(package):
                return package
    return None


def resolve_package_name(query: str) -> str:
    if not query:
        raise AuroraDownloadError("Package name is required.")
    trimmed = query.strip()
    url_package = _extract_package_from_url(trimmed)
    if url_package:
        return url_package
    if PACKAGE_NAME_RE.match(trimmed):
        return trimmed

    html = None
    errors = []
    query_encoded = quote_plus(trimmed)

    for template in PLAY_SUGGEST_URLS:
        url = template.format(query=query_encoded)
        try:
            raw = _fetch_url(url, timeout=8)
            payload = json.loads(_strip_xssi_prefix(raw))
        except (HTTPError, URLError) as exc:
            errors.append(str(exc))
            continue
        except Exception as exc:
            errors.append(str(exc))
            continue
        candidates = _extract_packages_from_json(payload)
        if candidates:
            return candidates[0]

    for template in PLAY_SEARCH_URLS:
        url = template.format(query=query_encoded)
        try:
            html = _fetch_url(url, timeout=10)
        except (HTTPError, URLError) as exc:
            errors.append(str(exc))
            continue
        except Exception as exc:
            errors.append(str(exc))
            continue

        candidates = _extract_package_candidates(html or "")
        if candidates:
            return candidates[0]
        fuzzy = _extract_fuzzy_packages(html or "")
        if fuzzy:
            return fuzzy[0]

    if html:
        raise AuroraDownloadError("No package found for that app name.")
    detail = errors[-1] if errors else "Unknown error"
    raise AuroraDownloadError(f"Failed to search Play Store: {detail}")


def download_apk(
    package_name: str,
    destination: Path,
    mode: str = "aurora",
    dispenser_url: Optional[str] = None,
    device_props: Optional[Path] = None,
    locale: Optional[str] = None,
) -> Path:
    normalized = mode.lower()
    if normalized in {"anonymous", "aurora"}:
        return _download_via_aurora_cli(
            package_name=package_name,
            destination=destination,
            dispenser_url=dispenser_url,
            device_props=device_props,
            locale=locale,
        )
    raise AuroraDownloadError(f"Unsupported aurora mode: {mode}")


def list_top_charts(
    *,
    chart: str = "TOP_SELLING_FREE",
    chart_type: str = "APPLICATION",
    limit: int = 200,
    dispenser_url: Optional[str] = None,
    device_props: Optional[Path] = None,
    locale: Optional[str] = None,
) -> list[str]:
    if not AURORA_DOWNLOADER_PATH.exists():
        raise AuroraDownloadError(
            "aurora-downloader binary not found. Run ./build-aurora.sh to build it."
        )
    cmd = [
        str(AURORA_DOWNLOADER_PATH),
        "--list-top-charts",
        "--chart",
        chart,
        "--chart-type",
        chart_type,
        "--chart-limit",
        str(limit),
    ]
    if dispenser_url:
        cmd += ["--dispenser-url", dispenser_url]
    if device_props:
        if not device_props.exists():
            raise AuroraDownloadError("device_props path does not exist.")
        cmd += ["--device-props", str(device_props)]
    if locale:
        cmd += ["--locale", locale]

    env = os.environ.copy()
    aurora_user_agent = env.get("AURORA_USER_AGENT")
    if aurora_user_agent:
        cmd += ["--user-agent", aurora_user_agent]
    aurora_dispenser_user_agent = env.get("AURORA_DISPENSER_USER_AGENT")
    if aurora_dispenser_user_agent:
        cmd += ["--dispenser-user-agent", aurora_dispenser_user_agent]
    aurora_java_home = env.get("AURORA_JAVA_HOME")
    if aurora_java_home:
        java_bin = Path(aurora_java_home) / "bin" / "java"
        if not java_bin.exists():
            raise AuroraDownloadError("AURORA_JAVA_HOME does not contain a java binary.")
        env["JAVA_HOME"] = str(Path(aurora_java_home).resolve())
        env["PATH"] = f"{env['JAVA_HOME']}/bin:{env.get('PATH', '')}"
    aurora_timeout = env.get("AURORA_TIMEOUT_SECONDS")
    if aurora_timeout:
        cmd += ["--timeout-seconds", aurora_timeout]
    aurora_retries = env.get("AURORA_DOWNLOAD_RETRIES")
    if aurora_retries:
        cmd += ["--download-retries", aurora_retries]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raw_error = result.stderr.strip() or result.stdout.strip()
        raise AuroraDownloadError(f"aurora-downloader failed: {raw_error}")

    raw = result.stdout.strip()
    if not raw:
        return []
    raw = raw.lstrip("\ufeff")
    try:
        data = json.loads(raw)
    except Exception as exc:
        data = _extract_json_array_from_output(raw)
        if data is None:
            snippet = raw[:300]
            raise AuroraDownloadError(
                f"aurora-downloader returned invalid JSON: {exc}. Output: {snippet}"
            ) from exc
    if isinstance(data, list):
        return [str(item) for item in data if str(item).strip()]
    return []


def _extract_json_array_from_output(text: str) -> Optional[list]:
    in_string = False
    escape = False
    depth = 0
    start = None
    for idx, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "[":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "]":
            if depth == 0:
                continue
            depth -= 1
            if depth == 0 and start is not None:
                candidate = text[start : idx + 1]
                try:
                    data = json.loads(candidate)
                except Exception:
                    start = None
                    continue
                if isinstance(data, list):
                    return data
                start = None
    return None


def _download_via_aurora_cli(
    package_name: str,
    destination: Path,
    dispenser_url: Optional[str],
    device_props: Optional[Path],
    locale: Optional[str],
) -> Path:
    if not AURORA_DOWNLOADER_PATH.exists():
        raise AuroraDownloadError(
            "aurora-downloader binary not found. Run ./build-aurora.sh to build it."
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    output_dir = destination.parent / f"{destination.stem}_files"
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"

    cmd = [
        str(AURORA_DOWNLOADER_PATH),
        "--package",
        package_name,
        "--output",
        str(destination),
        "--output-dir",
        str(output_dir),
        "--result",
        str(result_path),
    ]
    if dispenser_url:
        cmd += ["--dispenser-url", dispenser_url]
    if device_props:
        if not device_props.exists():
            raise AuroraDownloadError("device_props path does not exist.")
        cmd += ["--device-props", str(device_props)]
    if locale:
        cmd += ["--locale", locale]

    env = os.environ.copy()
    aurora_user_agent = env.get("AURORA_USER_AGENT")
    if aurora_user_agent:
        cmd += ["--user-agent", aurora_user_agent]
    aurora_dispenser_user_agent = env.get("AURORA_DISPENSER_USER_AGENT")
    if aurora_dispenser_user_agent:
        cmd += ["--dispenser-user-agent", aurora_dispenser_user_agent]
    aurora_java_home = env.get("AURORA_JAVA_HOME")
    if aurora_java_home:
        java_bin = Path(aurora_java_home) / "bin" / "java"
        if not java_bin.exists():
            raise AuroraDownloadError("AURORA_JAVA_HOME does not contain a java binary.")
        env["JAVA_HOME"] = str(Path(aurora_java_home).resolve())
        env["PATH"] = f"{env['JAVA_HOME']}/bin:{env.get('PATH', '')}"
    aurora_timeout = env.get("AURORA_TIMEOUT_SECONDS")
    if aurora_timeout:
        cmd += ["--timeout-seconds", aurora_timeout]
    aurora_retries = env.get("AURORA_DOWNLOAD_RETRIES")
    if aurora_retries:
        cmd += ["--download-retries", aurora_retries]

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raw_error = result.stderr.strip() or result.stdout.strip()
        if "UnknownHostException" in raw_error and "auroraoss.com" in raw_error:
            raise AuroraDownloadError(
                "aurora-downloader failed: unable to reach auroraoss.com. "
                "Check DNS/network access or set a custom dispenser URL."
            )
        if "SocketTimeoutException" in raw_error or "timeout" in raw_error.lower():
            raise AuroraDownloadError(
                "aurora-downloader failed: download timed out. "
                "Try again or increase timeouts (AURORA_TIMEOUT_SECONDS) "
                "and retries (AURORA_DOWNLOAD_RETRIES)."
            )
        if "AppNotFound" in raw_error:
            raise AuroraDownloadError(
                "aurora-downloader failed: app not found for this package. "
                "Check the package name or try different device props/locale."
            )
        raise AuroraDownloadError(f"aurora-downloader failed: {raw_error}")
    if not destination.exists():
        raise AuroraDownloadError("aurora-downloader completed but APK was not created.")
    return destination
