import json
import os
import re
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener, urlopen

from .config import BASE_DIR


TEXT_EXTENSIONS = {
    ".json",
    ".xml",
    ".txt",
    ".html",
    ".htm",
    ".js",
    ".properties",
    ".ini",
    ".cfg",
    ".yml",
    ".yaml",
}

MAX_FILE_BYTES = 50 * 1024 * 1024

PROJECT_ID_URL_RE = re.compile(r"https?://([a-z0-9-]{3,})\.firebaseio\.com", re.IGNORECASE)
PROJECT_ID_URL_ALT_RE = re.compile(
    r"https?://([a-z0-9-]{3,})-default-rtdb\.firebaseio\.com", re.IGNORECASE
)
PROJECT_ID_DB_APP_RE = re.compile(
    r"https?://([a-z0-9-]{3,})\.[a-z0-9-]+\.firebasedatabase\.app", re.IGNORECASE
)
DATABASE_URL_RE = re.compile(
    r"https?://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com", re.IGNORECASE
)
DATABASE_APP_URL_RE = re.compile(
    r"https?://[a-z0-9-]+\.[a-z0-9-]+\.firebasedatabase\.app", re.IGNORECASE
)
STORAGE_BUCKET_RE = re.compile(r"([a-z0-9-]+\.appspot\.com)", re.IGNORECASE)
STORAGE_APP_RE = re.compile(r"([a-z0-9-]+)\.firebasestorage\.app", re.IGNORECASE)
STORAGE_API_RE = re.compile(
    r"firebasestorage\.googleapis\.com/v0/b/([a-z0-9-]+)\.appspot\.com",
    re.IGNORECASE,
)
API_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
APP_ID_RE = re.compile(r"1:\d+:android:[0-9a-fA-F]{10,}")
STRING_RESOURCE_RE = re.compile(
    r"<string[^>]*name=[\"']([^\"']+)[\"'][^>]*>(.*?)</string>", re.IGNORECASE | re.DOTALL
)
META_DATA_RE = re.compile(
    r"<meta-data[^>]*android:name=[\"']([^\"']+)[\"'][^>]*android:value=[\"']([^\"']+)[\"']",
    re.IGNORECASE | re.DOTALL,
)

API_KEY_NAME_HINTS = {
    "google_api_key": "firebase_api_key",
    "google_crash_reporting_api_key": "firebase_api_key",
    "firebase_api_key": "firebase_api_key",
    "google_maps_key": "google_maps_api_key",
    "maps_api_key": "google_maps_api_key",
}

OPENFIREBASE_RULES_PATH = BASE_DIR / "OpenFirebase" / "openfirebase" / "firebase_rules.json"
OPENFIREBASE_PATTERNS: Optional[List[Tuple[str, re.Pattern, int]]] = None
OPENFIREBASE_FILTERED_DOMAINS = {
    "admob-gmats.uc.r.appspot.com",
    "example.appspot.com",
    "myservice.appspot.com",
    "test.firebaseio.com",
    "demo.firebaseio.com",
    "chrome-devtools-frontend",
}
OPENFIREBASE_INVALID_PROJECT_IDS = {
    "-default-rtdb",
    "chrome-devtools-frontend",
}
OPENFIREBASE_KIND_MAP = {
    "Google_API_Key": "firebase_api_key",
    "Other_Google_API_Key": "google_api_key",
}
OPENFIREBASE_DIR = BASE_DIR / "OpenFirebase"
OPENFIREBASE_WORDLIST_PATH = OPENFIREBASE_DIR / "openfirebase" / "wordlist" / "firestore-collections.txt"
OPENFIREBASE_INVALID_COLLECTION_PREFIXES = (
    "Describe protocol",
    "_tdc",
    ".append(",
)
OPENFIREBASE_FILTERED_COLLECTION_VALUES = {
    "service_disabled",
    "access_denied",
    "signal collection failed:",
    "received empty bid id",
}


@dataclass
class FirebaseTargets:
    project_ids: Set[str] = field(default_factory=set)
    api_keys: Set[str] = field(default_factory=set)
    api_key_details: Dict[str, Dict[str, Set[str]]] = field(default_factory=dict)
    app_ids: Set[str] = field(default_factory=set)
    database_urls: Set[str] = field(default_factory=set)
    storage_buckets: Set[str] = field(default_factory=set)
    firestore_collections: Set[str] = field(default_factory=set)
    package_names: Set[str] = field(default_factory=set)
    cert_sha1_list: List[str] = field(default_factory=list)
    items: List[Tuple[str, str]] = field(default_factory=list)
    _seen_items: Set[Tuple[str, str]] = field(default_factory=set, init=False, repr=False)

    def add_api_key(
        self,
        key: str,
        *,
        kind: Optional[str] = None,
        source: Optional[str] = None,
        resource: Optional[str] = None,
        detector: Optional[str] = None,
        item_name: Optional[str] = None,
    ) -> None:
        is_new = key not in self.api_keys
        self.api_keys.add(key)
        if is_new and item_name:
            self.record_item(item_name, key)
        details = self.api_key_details.setdefault(
            key, {"kinds": set(), "sources": set(), "resources": set(), "detectors": set()}
        )
        if kind:
            details["kinds"].add(kind)
        if source:
            details["sources"].add(source)
        if resource:
            details["resources"].add(resource)
        if detector:
            details["detectors"].add(detector)

    def record_item(self, name: str, value: str) -> None:
        key = (name, value)
        if key in self._seen_items:
            return
        self._seen_items.add(key)
        self.items.append((name, value))

    def add_package_name(self, package_name: str) -> None:
        if not package_name:
            return
        if package_name in self.package_names:
            return
        self.package_names.add(package_name)
        self.record_item("APK_Package_Name", package_name)

    def add_cert_sha1(self, cert_sha1: str) -> None:
        if not cert_sha1:
            return
        if cert_sha1 in self.cert_sha1_list:
            return
        self.cert_sha1_list.append(cert_sha1)
        self.record_item("APK_Certificate_SHA1", cert_sha1)

    def to_dict(self) -> Dict[str, object]:
        api_key_details = []
        for key in sorted(self.api_keys):
            details = self.api_key_details.get(key, {})
            api_key_details.append(
                {
                    "key": key,
                    "kinds": sorted(details.get("kinds", [])),
                    "sources": sorted(details.get("sources", [])),
                    "resources": sorted(details.get("resources", [])),
                    "detectors": sorted(details.get("detectors", [])),
                }
            )
        return {
            "project_ids": sorted(self.project_ids),
            "api_keys": sorted(self.api_keys),
            "api_key_details": api_key_details,
            "app_ids": sorted(self.app_ids),
            "database_urls": sorted(self.database_urls),
            "storage_buckets": sorted(self.storage_buckets),
            "firestore_collections": sorted(self.firestore_collections),
            "package_names": sorted(self.package_names),
            "cert_sha1_list": list(self.cert_sha1_list),
            "items": list(self.items),
        }


@dataclass
class AuthContext:
    enabled: bool
    firebase_auth: Optional[object]
    error: Optional[str] = None
    successes: Set[str] = field(default_factory=set)
    failures: Dict[str, str] = field(default_factory=dict)

    def token_for(self, project_id: str) -> Optional[str]:
        if not self.firebase_auth:
            return None
        try:
            return self.firebase_auth.get_auth_token(project_id)
        except Exception:
            return None


@dataclass
class HttpResponse:
    status: int
    body: bytes
    error: Optional[str] = None

    def json(self) -> Optional[Dict[str, object]]:
        try:
            return json.loads(self.body.decode("utf-8", errors="ignore"))
        except Exception:
            return None


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        if requests_per_second and requests_per_second > 0:
            self.min_interval = 1.0 / requests_per_second
        else:
            self.min_interval = 0.0
        self._last_request = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()


def _ensure_openfirebase_path() -> None:
    if not OPENFIREBASE_DIR.exists():
        return
    path = str(OPENFIREBASE_DIR)
    if path not in sys.path:
        sys.path.insert(0, path)


def _get_jadx_path() -> Optional[Path]:
    system_jadx = shutil.which("jadx")
    if system_jadx:
        return Path(system_jadx)
    tools_dir = OPENFIREBASE_DIR / "openfirebase" / "tools" / "jadx" / "bin"
    jadx_name = "jadx.bat" if os.name == "nt" else "jadx"
    candidate = tools_dir / jadx_name
    if candidate.exists():
        return candidate
    return None


def _jadx_available() -> bool:
    return _get_jadx_path() is not None


def _is_valid_collection_name(value: str) -> bool:
    if not value:
        return False
    lowered = value.strip().lower()
    if lowered in OPENFIREBASE_FILTERED_COLLECTION_VALUES:
        return False
    for prefix in OPENFIREBASE_INVALID_COLLECTION_PREFIXES:
        if value.startswith(prefix):
            return False
    return True


def _load_wordlist(path: Optional[Path]) -> List[str]:
    wordlist_path = path or OPENFIREBASE_WORDLIST_PATH
    if not wordlist_path or not wordlist_path.exists():
        return []
    entries: List[str] = []
    for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def _extract_jadx_items(
    apk_path: Path,
    *,
    timeout_seconds: Optional[int] = None,
    auto_install: bool = False,
) -> List[Tuple[str, str]]:
    if not auto_install and not _jadx_available():
        return []
    try:
        _ensure_openfirebase_path()
        from openfirebase.extractors.jadx_extractor import JADXExtractor  # type: ignore

        extractor = JADXExtractor(
            str(apk_path.parent),
            auto_install=auto_install,
            processing_mode="single",
            timeout_seconds=timeout_seconds,
        )
        if not extractor.jadx_available:
            return []
        return extractor.process_file(apk_path)
    except Exception:
        return []


def _extract_signature_data(apk_path: Path) -> Tuple[List[str], Optional[str]]:
    try:
        _ensure_openfirebase_path()
        from openfirebase.extractors.signature_extractor import SignatureExtractor  # type: ignore

        return SignatureExtractor.extract_apk_signature(apk_path)
    except Exception:
        return ([], None)


def _parse_dns_project_ids(path: Path) -> Set[str]:
    try:
        _ensure_openfirebase_path()
        from openfirebase.extractors.dns_parser import DNSParser  # type: ignore

        parser = DNSParser(str(OPENFIREBASE_RULES_PATH))
        return parser.parse_dns_file(str(path))
    except Exception:
        # Fallback: scan for known Firebase URL patterns in file
        ids: Set[str] = set()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ids
        for match in PROJECT_ID_URL_RE.finditer(text):
            ids.add(match.group(1))
        for match in PROJECT_ID_URL_ALT_RE.finditer(text):
            ids.add(match.group(1))
        for match in PROJECT_ID_DB_APP_RE.finditer(text):
            ids.add(match.group(1))
        for match in STORAGE_BUCKET_RE.finditer(text):
            value = match.group(1)
            if value.endswith(".appspot.com"):
                ids.add(value.replace(".appspot.com", ""))
        return ids


def _extract_project_id(value: str) -> Optional[str]:
    for regex in (PROJECT_ID_URL_RE, PROJECT_ID_URL_ALT_RE, PROJECT_ID_DB_APP_RE):
        match = regex.search(value)
        if match:
            project_id = match.group(1)
            if project_id and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
                return project_id
    storage_match = STORAGE_API_RE.search(value) or STORAGE_APP_RE.search(value)
    if storage_match:
        project_id = storage_match.group(1)
        if project_id and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
            return project_id
    return None

def extract_firebase_targets(
    apk_path: Path,
    fast_extract: bool = False,
    *,
    use_jadx: bool = False,
    jadx_auto_install: bool = False,
    jadx_timeout_seconds: Optional[int] = None,
    extract_signatures: bool = False,
) -> FirebaseTargets:
    targets = FirebaseTargets()
    if fast_extract:
        use_jadx = False

    package_name = _extract_package_name(apk_path)
    if package_name:
        targets.add_package_name(package_name)

    if extract_signatures:
        certs, sig_package = _extract_signature_data(apk_path)
        for cert_sha1 in certs:
            targets.add_cert_sha1(cert_sha1)
        if sig_package:
            targets.add_package_name(sig_package)

    if use_jadx:
        jadx_items = _extract_jadx_items(
            apk_path,
            timeout_seconds=jadx_timeout_seconds,
            auto_install=jadx_auto_install,
        )
        if jadx_items:
            _apply_openfirebase_items(jadx_items, targets)

    resources_xml = _extract_strings_resources(apk_path)
    if resources_xml:
        _scan_text(resources_xml, targets, source="resources/strings.xml")
        _scan_xml_resources(resources_xml, targets, source="resources/strings.xml")
        _scan_openfirebase_patterns(resources_xml, targets, source="resources/strings.xml")

    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.lower()
            if fast_extract and not name.endswith(".dex"):
                continue
            if info.file_size > MAX_FILE_BYTES:
                continue
            with archive.open(info) as handle:
                data = handle.read()

            if name.endswith("google-services.json"):
                _parse_google_services_json(data, targets, source=info.filename)

            if Path(name).suffix in TEXT_EXTENSIONS:
                text = data.decode("utf-8", errors="ignore")
                _scan_text(text, targets, source=info.filename)
                if name.endswith(".xml"):
                    _scan_xml_resources(text, targets, source=info.filename)
                _scan_openfirebase_patterns(text, targets, source=info.filename)
                continue

            for chunk in _extract_strings_from_binary(data):
                _scan_text(chunk, targets, source=f"{info.filename} (strings)")
                _scan_openfirebase_patterns(chunk, targets, source=f"{info.filename} (strings)")

    _add_default_urls(targets)
    return targets


def build_targets_from_project_ids(
    project_ids: Iterable[str],
    *,
    api_key: Optional[str] = None,
    app_id: Optional[str] = None,
    package_name: Optional[str] = None,
    cert_sha1_list: Optional[List[str]] = None,
) -> FirebaseTargets:
    targets = FirebaseTargets()
    for project_id in project_ids:
        project_id = project_id.strip()
        if not project_id:
            continue
        if project_id in OPENFIREBASE_INVALID_PROJECT_IDS:
            continue
        if project_id not in targets.project_ids:
            targets.project_ids.add(project_id)
            targets.record_item("Firebase_Project_ID", project_id)
    if api_key:
        targets.add_api_key(
            api_key,
            kind="firebase_api_key",
            detector="manual",
            item_name="Google_API_Key",
        )
    if app_id:
        targets.app_ids.add(app_id)
        targets.record_item("Google_App_ID", app_id)
    if package_name:
        targets.add_package_name(package_name)
    if cert_sha1_list:
        for cert in cert_sha1_list:
            targets.add_cert_sha1(cert)
    _add_default_urls(targets)
    return targets


def load_targets_from_resume(resume_path: Path) -> FirebaseTargets:
    targets = FirebaseTargets()
    if resume_path.is_dir():
        targets_json = resume_path / "targets.json"
        if targets_json.exists():
            return load_targets_from_json(targets_json)
        firebase_items = list(resume_path.glob("*_firebase_items.txt"))
        if firebase_items:
            return load_targets_from_openfirebase_file(firebase_items[0])
    if resume_path.is_file():
        if resume_path.name.endswith("_firebase_items.txt"):
            return load_targets_from_openfirebase_file(resume_path)
        if resume_path.name == "targets.json":
            return load_targets_from_json(resume_path)
    return targets


def load_targets_from_openfirebase_file(path: Path) -> FirebaseTargets:
    targets = FirebaseTargets()
    package_name = None
    current_header = None
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("===") and line.endswith("==="):
            package_name = line.strip("=").strip()
            if package_name:
                targets.add_package_name(package_name)
            continue
        if line.startswith("[") and line.endswith("]"):
            current_header = line[1:-1].strip()
            continue
        if current_header and line.startswith("- "):
            value = line[2:].strip()
            if value.endswith(")") and " (" in value:
                value = value.rsplit(" (", 1)[0].strip()
            _apply_openfirebase_items([(current_header, value)], targets)
    _add_default_urls(targets)
    return targets


def load_targets_from_json(path: Path) -> FirebaseTargets:
    targets = FirebaseTargets()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return targets
    items = data.get("items")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                _apply_openfirebase_items([(item[0], item[1])], targets)
    for project_id in data.get("project_ids", []) or []:
        if project_id not in targets.project_ids and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
            targets.project_ids.add(project_id)
    for api_key in data.get("api_keys", []) or []:
        targets.add_api_key(api_key, kind="firebase_api_key", detector="resume", item_name="Google_API_Key")
    for app_id in data.get("app_ids", []) or []:
        if app_id not in targets.app_ids:
            targets.app_ids.add(app_id)
            targets.record_item("Google_App_ID", app_id)
    for bucket in data.get("storage_buckets", []) or []:
        targets.storage_buckets.add(bucket)
    for url in data.get("database_urls", []) or []:
        targets.database_urls.add(url)
    for collection in data.get("firestore_collections", []) or []:
        if _is_valid_collection_name(collection):
            targets.firestore_collections.add(collection)
    for name in data.get("package_names", []) or []:
        targets.add_package_name(name)
    for cert_sha1 in data.get("cert_sha1_list", []) or []:
        targets.add_cert_sha1(cert_sha1)
    _add_default_urls(targets)
    return targets


def _load_resume_auth_data(auth_file: Optional[Path]) -> Dict[str, Dict[str, object]]:
    if not auth_file:
        return {}
    try:
        _ensure_openfirebase_path()
        from openfirebase.handlers.auth_data_handler import AuthDataHandler  # type: ignore

        return AuthDataHandler.load_auth_data(str(auth_file))
    except Exception:
        return {}


def _build_auth_data(
    targets: FirebaseTargets,
    *,
    manual_api_key: Optional[str] = None,
    manual_app_id: Optional[str] = None,
    resume_auth_file: Optional[Path] = None,
) -> Dict[str, Dict[str, object]]:
    auth_data: Dict[str, Dict[str, object]] = {}

    if targets.items:
        try:
            _ensure_openfirebase_path()
            from openfirebase.utils import extract_enhanced_auth_data  # type: ignore

            package_name = next(iter(sorted(targets.package_names)), "apk")
            auth_data = extract_enhanced_auth_data({package_name: list(targets.items)})
        except Exception:
            auth_data = {}

    if not auth_data:
        for project_id in targets.project_ids:
            auth_data[project_id] = {
                "main_project_id": project_id,
                "api_keys": list(targets.api_keys),
                "app_id": next(iter(targets.app_ids), None),
                "cert_sha1_list": list(targets.cert_sha1_list),
                "package_name": next(iter(targets.package_names), None),
            }

    if manual_api_key or manual_app_id:
        for project_id in targets.project_ids:
            entry = auth_data.setdefault(project_id, {})
            api_keys = list(entry.get("api_keys") or [])
            if manual_api_key and manual_api_key not in api_keys:
                api_keys.append(manual_api_key)
            entry["api_keys"] = api_keys
            if manual_app_id:
                entry["app_id"] = manual_app_id

    resume_auth_data = _load_resume_auth_data(resume_auth_file)
    if resume_auth_data:
        for project_id, entry_data in resume_auth_data.items():
            if project_id not in targets.project_ids:
                continue
            entry = auth_data.setdefault(project_id, {})
            api_keys = list(entry.get("api_keys") or [])
            resume_key = entry_data.get("api_key")
            if resume_key and resume_key not in api_keys:
                api_keys.append(resume_key)
            entry["api_keys"] = api_keys
            if entry_data.get("app_id"):
                entry["app_id"] = entry_data.get("app_id")
            if entry_data.get("package_name"):
                entry["package_name"] = entry_data.get("package_name")
            cert_sha1_list = list(entry.get("cert_sha1_list") or [])
            resume_cert = entry_data.get("cert_sha1")
            if resume_cert and resume_cert not in cert_sha1_list:
                cert_sha1_list.append(resume_cert)
            entry["cert_sha1_list"] = cert_sha1_list

    return auth_data


def _init_auth_context(
    targets: FirebaseTargets,
    *,
    auth_email: Optional[str],
    auth_password: Optional[str],
    limiter: RateLimiter,
    timeout_seconds: float,
    proxy: Optional[str] = None,
    resume_auth_file: Optional[Path] = None,
    manual_api_key: Optional[str] = None,
    manual_app_id: Optional[str] = None,
    auth_data: Optional[Dict[str, Dict[str, object]]] = None,
    output_dir: Optional[Path] = None,
) -> AuthContext:
    if not auth_email and not auth_password:
        return AuthContext(enabled=False, firebase_auth=None)
    if not auth_email or not auth_password:
        return AuthContext(enabled=True, firebase_auth=None, error="Missing auth email or password.")

    if auth_data is None:
        auth_data = _build_auth_data(
            targets,
            manual_api_key=manual_api_key,
            manual_app_id=manual_app_id,
            resume_auth_file=resume_auth_file,
        )
    if not auth_data and not targets.api_keys and not manual_api_key:
        return AuthContext(enabled=True, firebase_auth=None, error="Missing API key from APK; cannot authenticate.")

    try:
        _ensure_openfirebase_path()
        from openfirebase.core.auth import FirebaseAuth  # type: ignore
    except Exception as exc:
        return AuthContext(enabled=True, firebase_auth=None, error=f"Auth dependencies unavailable: {exc}")

    firebase_auth = FirebaseAuth(timeout=int(max(timeout_seconds, 1)), proxy=proxy)
    context = AuthContext(enabled=True, firebase_auth=firebase_auth)

    expected_project_ids = list(sorted(targets.project_ids))
    for project_id in sorted(targets.project_ids):
        entry = auth_data.get(project_id, {})
        api_keys = list(entry.get("api_keys") or [])
        if not api_keys:
            context.failures[project_id] = "No API keys for project."
            continue
        package_name = entry.get("package_name") or next(iter(targets.package_names), None)
        cert_sha1_list = list(entry.get("cert_sha1_list") or []) or list(targets.cert_sha1_list)
        app_id = entry.get("app_id")
        limiter.wait()
        result = firebase_auth.create_account_with_multiple_keys(
            project_id,
            api_keys,
            auth_email,
            auth_password,
            expected_project_ids,
            package_name,
            cert_sha1_list or None,
            app_id,
            str(output_dir) if output_dir else None,
        )
        if result:
            _, validated_project_id = result
            context.successes.add(validated_project_id or project_id)
        else:
            context.failures[project_id] = "Authentication failed."

    if not context.successes and not context.error:
        context.error = "Authentication failed for all projects."

    return context


def _extract_strings_from_binary(data: bytes, min_len: int = 4) -> Iterable[str]:
    current: List[str] = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                yield "".join(current)
            current = []
    if len(current) >= min_len:
        yield "".join(current)


def _extract_package_name(apk_path: Path) -> Optional[str]:
    try:
        from androguard.core.apk import APK  # type: ignore

        apk = APK(str(apk_path))
        return apk.get_package()
    except Exception:
        return None


def _apply_openfirebase_items(items: List[Tuple[str, str]], targets: FirebaseTargets) -> None:
    for name, value in items:
        if not value:
            continue
        value = value.strip()
        targets.record_item(name, value)

        if name in {"Firebase_Project_ID", "Other_Firebase_Project_ID"}:
            if value in OPENFIREBASE_INVALID_PROJECT_IDS:
                continue
            targets.project_ids.add(value)
            continue

        if name in {"Google_API_Key", "Other_Google_API_Key"}:
            targets.add_api_key(
                value,
                kind=OPENFIREBASE_KIND_MAP.get(name),
                detector="openfirebase",
                item_name=name,
            )
            continue

        if name in {"Google_App_ID", "Other_Google_App_ID"}:
            if value not in targets.app_ids:
                targets.app_ids.add(value)
            continue

        if name.startswith("Firebase_Database"):
            db_url = _normalize_database_url(value)
            if db_url:
                targets.database_urls.add(db_url)
                _add_project_id_from_url(db_url, targets)
            continue

        if name.startswith("Firebase_Storage"):
            bucket = _normalize_storage_bucket(value)
            if bucket:
                targets.storage_buckets.add(bucket)
                _add_project_id_from_url(bucket, targets)
            continue

        if name == "Firestore_Collection_Name":
            if _is_valid_collection_name(value):
                targets.firestore_collections.add(value)
            continue

        if name == "APK_Package_Name":
            targets.add_package_name(value)
            continue

        if name == "APK_Certificate_SHA1":
            targets.add_cert_sha1(value)
            continue

def _scan_text(text: str, targets: FirebaseTargets, source: Optional[str] = None) -> None:
    if "firebase" not in text and "appspot" not in text and "AIza" not in text:
        return

    for match in API_KEY_RE.finditer(text):
        kind = _infer_api_key_kind(text, source)
        item_name = "Google_API_Key" if kind == "firebase_api_key" else "Other_Google_API_Key"
        targets.add_api_key(
            match.group(0),
            kind=kind,
            source=source,
            detector="regex",
            item_name=item_name,
        )

    for match in APP_ID_RE.finditer(text):
        app_id = match.group(0)
        if app_id not in targets.app_ids:
            targets.app_ids.add(app_id)
            targets.record_item("Other_Google_App_ID", app_id)

    for match in DATABASE_URL_RE.finditer(text):
        targets.database_urls.add(match.group(0))

    for match in DATABASE_APP_URL_RE.finditer(text):
        url = match.group(0)
        targets.database_urls.add(url)
        _add_project_id_from_url(url, targets)

    for match in PROJECT_ID_URL_RE.finditer(text):
        project_id = match.group(1)
        if project_id and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
            targets.project_ids.add(project_id)
            targets.record_item("Other_Firebase_Project_ID", project_id)

    for match in PROJECT_ID_URL_ALT_RE.finditer(text):
        project_id = match.group(1)
        if project_id and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
            targets.project_ids.add(project_id)
            targets.record_item("Other_Firebase_Project_ID", project_id)

    for match in STORAGE_BUCKET_RE.finditer(text):
        targets.storage_buckets.add(match.group(1))

    for match in STORAGE_APP_RE.finditer(text):
        bucket = f"{match.group(1)}.firebasestorage.app"
        targets.storage_buckets.add(bucket)
        _add_project_id_from_url(bucket, targets)


def _parse_google_services_json(
    raw: bytes, targets: FirebaseTargets, source: Optional[str] = None
) -> None:
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return

    project_info = data.get("project_info", {})
    project_id = project_info.get("project_id")
    if project_id:
        targets.project_ids.add(project_id)
        targets.record_item("Firebase_Project_ID", project_id)

    storage_bucket = project_info.get("storage_bucket")
    if storage_bucket:
        targets.storage_buckets.add(storage_bucket)

    firebase_url = project_info.get("firebase_url")
    if firebase_url:
        targets.database_urls.add(firebase_url)

    for client in data.get("client", []):
        client_info = client.get("client_info", {})
        app_id = client_info.get("mobilesdk_app_id")
        if app_id:
            targets.app_ids.add(app_id)
            targets.record_item("Google_App_ID", app_id)
        android_info = client_info.get("android_client_info") or {}
        package_name = android_info.get("package_name")
        if package_name:
            targets.add_package_name(package_name)
        for api_key in client.get("api_key", []):
            key = api_key.get("current_key")
            if key:
                targets.add_api_key(
                    key,
                    kind="firebase_api_key",
                    source=source,
                    resource="google-services.json",
                    detector="google_services",
                    item_name="Google_API_Key",
                )


def _add_default_urls(targets: FirebaseTargets) -> None:
    for project_id in list(targets.project_ids):
        targets.database_urls.add(f"https://{project_id}.firebaseio.com")
        targets.database_urls.add(f"https://{project_id}-default-rtdb.firebaseio.com")
        targets.storage_buckets.add(f"{project_id}.appspot.com")


def _extract_strings_resources(apk_path: Path) -> str:
    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:
        return ""

    try:
        apk = APK(str(apk_path))
        resources = apk.get_android_resources()
        if not resources:
            return ""
        string_resources = resources.get_strings_resources()
        if isinstance(string_resources, dict):
            xml_lines = ["<resources>"]
            for key, value in string_resources.items():
                if not isinstance(value, str):
                    continue
                xml_lines.append(f'<string name="{key}">{value}</string>')
            xml_lines.append("</resources>")
            return "\n".join(xml_lines)
        if isinstance(string_resources, (bytes, bytearray)):
            try:
                return string_resources.decode("utf-8", errors="ignore")
            except Exception:
                return ""
        return ""
    except Exception:
        return ""


def _load_openfirebase_patterns() -> List[Tuple[str, re.Pattern, int]]:
    global OPENFIREBASE_PATTERNS
    if OPENFIREBASE_PATTERNS is not None:
        return OPENFIREBASE_PATTERNS
    patterns: List[Tuple[str, re.Pattern, int]] = []
    if not OPENFIREBASE_RULES_PATH.exists():
        OPENFIREBASE_PATTERNS = patterns
        return patterns
    try:
        data = json.loads(OPENFIREBASE_RULES_PATH.read_text(encoding="utf-8"))
        for name, config in data.get("patterns", {}).items():
            if isinstance(config, dict):
                pattern = config.get("pattern")
                capture_group = int(config.get("capture_group", 0))
            else:
                pattern = config
                capture_group = 0
            if not pattern:
                continue
            patterns.append((name, re.compile(pattern, re.IGNORECASE), capture_group))
    except Exception:
        patterns = []
    OPENFIREBASE_PATTERNS = patterns
    return patterns


def _scan_openfirebase_patterns(text: str, targets: FirebaseTargets, source: Optional[str]) -> None:
    patterns = _load_openfirebase_patterns()
    if not patterns:
        return
    for name, regex, capture_group in patterns:
        for match in regex.finditer(text):
            if capture_group and match.lastindex and capture_group <= match.lastindex:
                value = match.group(capture_group)
            else:
                value = match.group(0)
            if not value:
                continue
            value = value.strip()
            if name not in {"Firebase_Project_ID", "Other_Firebase_Project_ID"}:
                value = value.rstrip("/")
            if any(domain in value.lower() for domain in OPENFIREBASE_FILTERED_DOMAINS):
                continue
            if name in {"Firebase_Project_ID", "Other_Firebase_Project_ID"}:
                if value in OPENFIREBASE_INVALID_PROJECT_IDS:
                    continue
                targets.record_item(name, value)
                targets.project_ids.add(value)
                continue
            if name == "Firestore_Collection_Name":
                if _is_valid_collection_name(value):
                    targets.record_item(name, value)
                    targets.firestore_collections.add(value)
                continue
            targets.record_item(name, value)
            if name in {"Google_API_Key", "Other_Google_API_Key"}:
                targets.add_api_key(
                    value,
                    kind=OPENFIREBASE_KIND_MAP.get(name),
                    source=source,
                    resource="strings.xml",
                    detector="openfirebase",
                    item_name=name,
                )
                continue
            if name in {"Google_App_ID", "Other_Google_App_ID"}:
                targets.app_ids.add(value)
                continue
            if name.startswith("Firebase_Database"):
                db_url = _normalize_database_url(value)
                if db_url:
                    targets.database_urls.add(db_url)
                    _add_project_id_from_url(db_url, targets)
                continue
            if name.startswith("Firebase_Storage"):
                bucket = _normalize_storage_bucket(value)
                if bucket:
                    targets.storage_buckets.add(bucket)
                    _add_project_id_from_url(bucket, targets)
                continue


def _add_project_id_from_url(value: str, targets: FirebaseTargets) -> None:
    for regex in (PROJECT_ID_URL_RE, PROJECT_ID_URL_ALT_RE, PROJECT_ID_DB_APP_RE):
        match = regex.search(value)
        if match:
            project_id = match.group(1)
            if project_id and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
                if project_id not in targets.project_ids:
                    targets.project_ids.add(project_id)
                    targets.record_item("Other_Firebase_Project_ID", project_id)
            return
    storage_match = STORAGE_API_RE.search(value) or STORAGE_APP_RE.search(value)
    if storage_match:
        project_id = storage_match.group(1)
        if project_id and project_id not in OPENFIREBASE_INVALID_PROJECT_IDS:
            if project_id not in targets.project_ids:
                targets.project_ids.add(project_id)
                targets.record_item("Other_Firebase_Project_ID", project_id)


def _normalize_database_url(value: str) -> Optional[str]:
    match = re.match(r"^(https?://)?([^/]+)", value.strip())
    if not match:
        return None
    scheme = match.group(1) or "https://"
    host = match.group(2)
    if not host:
        return None
    return f"{scheme}{host}"


def _normalize_storage_bucket(value: str) -> Optional[str]:
    text = value.strip()
    api_match = STORAGE_API_RE.search(text)
    if api_match:
        return f"{api_match.group(1)}.appspot.com"
    appspot_match = STORAGE_BUCKET_RE.search(text)
    if appspot_match:
        return appspot_match.group(1)
    app_match = STORAGE_APP_RE.search(text)
    if app_match:
        return f"{app_match.group(1)}.firebasestorage.app"
    return None


def _scan_xml_resources(text: str, targets: FirebaseTargets, source: Optional[str]) -> None:
    for name, value in STRING_RESOURCE_RE.findall(text):
        for match in API_KEY_RE.finditer(value):
            kind = _classify_resource_name(name)
            item_name = "Google_API_Key" if kind == "firebase_api_key" else "Other_Google_API_Key"
            targets.add_api_key(
                match.group(0),
                kind=kind,
                source=source,
                resource=name,
                detector="xml_resource",
                item_name=item_name,
            )

    for meta_name, meta_value in META_DATA_RE.findall(text):
        for match in API_KEY_RE.finditer(meta_value):
            kind = _classify_resource_name(meta_name) or _infer_api_key_kind(meta_name, source)
            item_name = "Google_API_Key" if kind == "firebase_api_key" else "Other_Google_API_Key"
            targets.add_api_key(
                match.group(0),
                kind=kind,
                source=source,
                resource=meta_name,
                detector="xml_resource",
                item_name=item_name,
            )


def _classify_resource_name(name: str) -> Optional[str]:
    lowered = name.lower()
    for key, kind in API_KEY_NAME_HINTS.items():
        if key in lowered:
            return kind
    if "com.google.android.geo.api_key" in lowered or "maps" in lowered:
        return "google_maps_api_key"
    if "firebase" in lowered:
        return "firebase_api_key"
    return None


def _infer_api_key_kind(text: str, source: Optional[str]) -> Optional[str]:
    haystack = f"{source or ''} {text}".lower()
    if "google-services.json" in haystack:
        return "firebase_api_key"
    if "firebase" in haystack or "firebaseio" in haystack or "appspot" in haystack:
        return "firebase_api_key"
    if "maps" in haystack or "com.google.android.geo.api_key" in haystack:
        return "google_maps_api_key"
    return "google_api_key"


def scan_firebase_targets(
    targets: FirebaseTargets,
    write_enabled: bool,
    scan_rate: float,
    timeout_seconds: float,
    auth_email: Optional[str] = None,
    auth_password: Optional[str] = None,
    *,
    output_dir: Optional[Path] = None,
    read_config: bool = True,
    fuzz_collections: bool = False,
    fuzz_wordlist: Optional[Path] = None,
    proxy: Optional[str] = None,
    resume_auth_file: Optional[Path] = None,
    manual_api_key: Optional[str] = None,
    manual_app_id: Optional[str] = None,
) -> Dict[str, object]:
    limiter = RateLimiter(scan_rate)
    auth_data = _build_auth_data(
        targets,
        manual_api_key=manual_api_key,
        manual_app_id=manual_app_id,
        resume_auth_file=resume_auth_file,
    )
    if auth_data and targets.project_ids:
        auth_data = {pid: data for pid, data in auth_data.items() if pid in targets.project_ids}
    auth_context = _init_auth_context(
        targets,
        auth_email=auth_email,
        auth_password=auth_password,
        limiter=limiter,
        timeout_seconds=timeout_seconds,
        proxy=proxy,
        resume_auth_file=resume_auth_file,
        manual_api_key=manual_api_key,
        manual_app_id=manual_app_id,
        auth_data=auth_data,
        output_dir=output_dir,
    )

    results = {
        "targets": targets.to_dict(),
        "auth": {
            "enabled": bool(auth_context.enabled),
            "success": bool(auth_context.successes),
            "error": auth_context.error,
            "email": auth_email if auth_context.enabled else None,
            "successful_projects": sorted(auth_context.successes),
            "failed_projects": auth_context.failures,
        },
        "services": {},
    }

    results["services"]["rtdb"] = _scan_rtdb(
        sorted(targets.database_urls),
        auth_context,
        write_enabled,
        limiter,
        timeout_seconds,
        proxy=proxy,
    )
    results["services"]["firestore"] = _scan_firestore(
        sorted(targets.project_ids),
        targets.firestore_collections,
        auth_context,
        write_enabled,
        limiter,
        timeout_seconds,
        fuzz_collections=fuzz_collections,
        fuzz_wordlist=fuzz_wordlist,
        proxy=proxy,
    )
    results["services"]["storage"] = _scan_storage(
        sorted(targets.storage_buckets),
        auth_context,
        write_enabled,
        limiter,
        timeout_seconds,
        proxy=proxy,
    )
    if read_config:
        results["services"]["remote_config"] = _scan_remote_config(
            auth_data,
            limiter,
            timeout_seconds,
            proxy=proxy,
            output_dir=output_dir,
        )

    if output_dir:
        _write_open_only_files(results, output_dir)

    results["summary"] = _build_summary(results)
    return results


def _write_open_only_files(results: Dict[str, object], output_dir: Path) -> None:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return
    services = results.get("services") or {}

    rtdb_checks = (services.get("rtdb") or {}).get("checks") or []
    open_rtdb = [
        c.get("target")
        for c in rtdb_checks
        if c.get("target") and (c.get("read") or c.get("auth_read"))
    ]
    if open_rtdb:
        (output_dir / "database_open_only.txt").write_text(
            "\n".join(sorted(set(open_rtdb))) + "\n", encoding="utf-8"
        )

    storage_checks = (services.get("storage") or {}).get("checks") or []
    open_storage = [
        c.get("target")
        for c in storage_checks
        if c.get("target") and (c.get("read") or c.get("auth_read"))
    ]
    if open_storage:
        (output_dir / "storage_open_only.txt").write_text(
            "\n".join(sorted(set(open_storage))) + "\n", encoding="utf-8"
        )

    firestore_checks = (services.get("firestore") or {}).get("checks") or []
    open_firestore = []
    for c in firestore_checks:
        if not (c.get("read") or c.get("auth_read")):
            continue
        if c.get("has_data") is False:
            continue
        collection = c.get("collection")
        target = c.get("target")
        if target and collection:
            open_firestore.append(f"{target}:{collection}")
    if open_firestore:
        (output_dir / "firestore_open_only.txt").write_text(
            "\n".join(sorted(set(open_firestore))) + "\n", encoding="utf-8"
        )

    config_checks = (services.get("remote_config") or {}).get("checks") or []
    open_config = [
        c.get("target")
        for c in config_checks
        if c.get("target") and c.get("read")
    ]
    if open_config:
        (output_dir / "config_open_only.txt").write_text(
            "\n".join(sorted(set(open_config))) + "\n", encoding="utf-8"
        )


def _scan_rtdb(
    base_urls: List[str],
    auth_context: AuthContext,
    write_enabled: bool,
    limiter: RateLimiter,
    timeout_seconds: float,
    *,
    proxy: Optional[str] = None,
) -> Dict[str, object]:
    checks = []
    for base_url in base_urls:
        project_id = _extract_project_id(base_url)
        read_url = f"{base_url}/.json"
        read_params = {"limitToFirst": "1"}
        limiter.wait()
        read_resp = _request(
            "GET",
            read_url + "?" + urlencode(read_params),
            None,
            {},
            timeout_seconds,
            proxy=proxy,
        )
        read_error = (read_resp.json() or {}).get("error") if read_resp.status < 400 else read_resp.error
        read_ok = read_resp.status < 400 and not read_error
        read_reason = None
        if read_resp.status == 404:
            body_text = read_resp.body.decode("utf-8", errors="ignore").lower()
            if "locked" in body_text or "deactivated" in body_text:
                read_reason = "locked"

        auth_read_ok = None
        auth_read_status = None
        if read_resp.status in (401, 403) and auth_context.enabled and project_id:
            token = auth_context.token_for(project_id)
            if token:
                limiter.wait()
                auth_read_resp = _request(
                    "GET",
                    read_url + "?" + urlencode({**read_params, "auth": token}),
                    None,
                    {},
                    timeout_seconds,
                    proxy=proxy,
                )
                auth_read_error = (auth_read_resp.json() or {}).get("error") if auth_read_resp.status < 400 else auth_read_resp.error
                auth_read_ok = auth_read_resp.status < 400 and not auth_read_error
                auth_read_status = auth_read_resp.status

        write_ok = False
        write_error = None
        write_status = None
        auth_write_ok = None
        auth_write_status = None
        auth_write_params = None
        if write_enabled:
            payload = json.dumps({"droidhunter": "write-check", "ts": _iso_now()}).encode("utf-8")
            write_url = f"{base_url}/droidhunter-write-check.json"
            limiter.wait()
            write_resp = _request(
                "PUT",
                write_url,
                payload,
                {"Content-Type": "application/json"},
                timeout_seconds,
                proxy=proxy,
            )
            write_error = (write_resp.json() or {}).get("error") if write_resp.status < 400 else write_resp.error
            write_ok = write_resp.status < 400 and not write_error
            write_status = write_resp.status
            if not write_ok and write_resp.status in (401, 403) and auth_context.enabled and project_id:
                token = auth_context.token_for(project_id)
                if token:
                    auth_write_params = {"auth": token}
                    limiter.wait()
                    auth_write_resp = _request(
                        "PUT",
                        write_url + "?" + urlencode(auth_write_params),
                        payload,
                        {"Content-Type": "application/json"},
                        timeout_seconds,
                        proxy=proxy,
                    )
                    auth_write_error = (
                        (auth_write_resp.json() or {}).get("error")
                        if auth_write_resp.status < 400
                        else auth_write_resp.error
                    )
                    auth_write_ok = auth_write_resp.status < 400 and not auth_write_error
                    auth_write_status = auth_write_resp.status
            if write_ok:
                limiter.wait()
                _request(
                    "DELETE",
                    write_url,
                    None,
                    {},
                    timeout_seconds,
                    proxy=proxy,
                )
            elif auth_write_ok and auth_write_params:
                limiter.wait()
                _request(
                    "DELETE",
                    write_url + "?" + urlencode(auth_write_params),
                    None,
                    {},
                    timeout_seconds,
                    proxy=proxy,
                )

        check = {
            "target": base_url,
            "read": read_ok,
            "read_status": read_resp.status,
            "read_reason": read_reason,
            "auth_read": auth_read_ok,
            "auth_read_status": auth_read_status,
            "write": write_ok if write_enabled else None,
            "write_status": write_status if write_enabled else None,
            "auth_write": auth_write_ok,
            "auth_write_status": auth_write_status,
            "error": write_error or read_error,
        }
        checks.append(check)

        if read_resp.status == 404:
            body_text = read_resp.body.decode("utf-8", errors="ignore")
            region_match = re.search(r"https://[^\"']+\\.firebasedatabase\\.app", body_text)
            if region_match:
                redirect_url = region_match.group(0)
                if not redirect_url.endswith("/.json"):
                    redirect_base = redirect_url.rstrip("/")
                else:
                    redirect_base = redirect_url.rsplit("/.json", 1)[0]
                if redirect_base not in base_urls:
                    limiter.wait()
                    redirect_resp = _request(
                        "GET",
                        redirect_base + "/.json?limitToFirst=1",
                        None,
                        {},
                        timeout_seconds,
                        proxy=proxy,
                    )
                    redirect_error = (
                        (redirect_resp.json() or {}).get("error")
                        if redirect_resp.status < 400
                        else redirect_resp.error
                    )
                    checks.append(
                        {
                            "target": redirect_base,
                            "read": redirect_resp.status < 400 and not redirect_error,
                            "read_status": redirect_resp.status,
                            "read_reason": "region_redirect",
                            "auth_read": None,
                            "auth_read_status": None,
                            "write": None,
                            "write_status": None,
                            "auth_write": None,
                            "auth_write_status": None,
                            "error": redirect_error,
                        }
                    )

    return {"checks": checks}


def _scan_firestore(
    project_ids: List[str],
    collections: Set[str],
    auth_context: AuthContext,
    write_enabled: bool,
    limiter: RateLimiter,
    timeout_seconds: float,
    *,
    fuzz_collections: bool = False,
    fuzz_wordlist: Optional[Path] = None,
    proxy: Optional[str] = None,
) -> Dict[str, object]:
    checks = []
    write_checks = []
    base_collections = set(collections or [])
    base_collections.add("users")
    fuzz_list = _load_wordlist(fuzz_wordlist) if fuzz_collections else []
    for project_id in project_ids:
        base_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        token = auth_context.token_for(project_id) if auth_context.enabled else None
        had_public_access = False

        for collection_name in sorted(base_collections):
            url = f"{base_url}/{collection_name}"
            limiter.wait()
            read_resp = _request("GET", url, None, {}, timeout_seconds, proxy=proxy)
            read_error = (read_resp.json() or {}).get("error") if read_resp.status < 400 else read_resp.error
            read_ok = read_resp.status < 400 and not read_error
            has_data = None
            if read_ok:
                try:
                    payload = read_resp.json() or {}
                    has_data = bool(payload.get("documents"))
                except Exception:
                    has_data = None
                had_public_access = True

            auth_read_ok = None
            auth_read_status = None
            if read_resp.status in (401, 403) and token:
                limiter.wait()
                auth_resp = _request(
                    "GET",
                    url,
                    None,
                    {"Authorization": f"Bearer {token}"},
                    timeout_seconds,
                    proxy=proxy,
                )
                auth_error = (auth_resp.json() or {}).get("error") if auth_resp.status < 400 else auth_resp.error
                auth_read_ok = auth_resp.status < 400 and not auth_error
                auth_read_status = auth_resp.status
                if auth_read_ok:
                    had_public_access = True
                    try:
                        payload = auth_resp.json() or {}
                        has_data = bool(payload.get("documents"))
                    except Exception:
                        has_data = None

            checks.append(
                {
                    "target": project_id,
                    "collection": collection_name,
                    "read": read_ok,
                    "read_status": read_resp.status,
                    "auth_read": auth_read_ok,
                    "auth_read_status": auth_read_status,
                    "has_data": has_data,
                    "error": read_error,
                }
            )

        if write_enabled:
            doc_id = f"droidhunter-{int(time.time())}"
            write_url = f"{base_url}/droidhunter-checks?documentId={doc_id}"
            payload = json.dumps(
                {
                    "fields": {
                        "droidhunter": {"stringValue": "write-check"},
                        "timestamp": {"timestampValue": _iso_now()},
                    }
                }
            ).encode("utf-8")
            limiter.wait()
            write_resp = _request(
                "POST",
                write_url,
                payload,
                {"Content-Type": "application/json"},
                timeout_seconds,
                proxy=proxy,
            )
            write_error = (write_resp.json() or {}).get("error") if write_resp.status < 400 else write_resp.error
            write_ok = write_resp.status < 400 and not write_error
            auth_write_ok = None
            auth_write_status = None
            auth_headers = None
            if not write_ok and write_resp.status in (401, 403) and token:
                limiter.wait()
                auth_headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
                auth_write_resp = _request(
                    "POST",
                    write_url,
                    payload,
                    auth_headers,
                    timeout_seconds,
                    proxy=proxy,
                )
                auth_write_error = (
                    (auth_write_resp.json() or {}).get("error")
                    if auth_write_resp.status < 400
                    else auth_write_resp.error
                )
                auth_write_ok = auth_write_resp.status < 400 and not auth_write_error
                auth_write_status = auth_write_resp.status
            if write_ok:
                limiter.wait()
                _request(
                    "DELETE",
                    f"{base_url}/droidhunter-checks/{doc_id}",
                    None,
                    {},
                    timeout_seconds,
                    proxy=proxy,
                )
            elif auth_write_ok and auth_headers:
                limiter.wait()
                _request(
                    "DELETE",
                    f"{base_url}/droidhunter-checks/{doc_id}",
                    None,
                    auth_headers,
                    timeout_seconds,
                    proxy=proxy,
                )
            write_checks.append(
                {
                    "target": project_id,
                    "write": write_ok,
                    "write_status": write_resp.status,
                    "auth_write": auth_write_ok,
                    "auth_write_status": auth_write_status,
                    "error": write_error,
                }
            )

        if fuzz_list and had_public_access:
            for collection_name in fuzz_list:
                if collection_name in base_collections:
                    continue
                url = f"{base_url}/{collection_name}"
                limiter.wait()
                fuzz_resp = _request("GET", url, None, {}, timeout_seconds, proxy=proxy)
                fuzz_error = (
                    (fuzz_resp.json() or {}).get("error") if fuzz_resp.status < 400 else fuzz_resp.error
                )
                if fuzz_resp.status == 200 and not fuzz_error:
                    try:
                        payload = fuzz_resp.json() or {}
                        has_data = bool(payload.get("documents"))
                    except Exception:
                        has_data = None
                    if has_data:
                        checks.append(
                            {
                                "target": project_id,
                                "collection": collection_name,
                                "read": True,
                                "read_status": fuzz_resp.status,
                                "auth_read": None,
                                "auth_read_status": None,
                                "has_data": has_data,
                                "fuzzed": True,
                                "error": None,
                            }
                        )
                if fuzz_resp.status in (401, 403) and token:
                    limiter.wait()
                    fuzz_auth_resp = _request(
                        "GET",
                        url,
                        None,
                        {"Authorization": f"Bearer {token}"},
                        timeout_seconds,
                        proxy=proxy,
                    )
                    fuzz_auth_error = (
                        (fuzz_auth_resp.json() or {}).get("error")
                        if fuzz_auth_resp.status < 400
                        else fuzz_auth_resp.error
                    )
                    if fuzz_auth_resp.status == 200 and not fuzz_auth_error:
                        try:
                            payload = fuzz_auth_resp.json() or {}
                            has_data = bool(payload.get("documents"))
                        except Exception:
                            has_data = None
                        if has_data:
                            checks.append(
                                {
                                    "target": project_id,
                                    "collection": collection_name,
                                    "read": False,
                                    "read_status": None,
                                    "auth_read": True,
                                    "auth_read_status": fuzz_auth_resp.status,
                                    "has_data": has_data,
                                    "fuzzed": True,
                                    "error": None,
                                }
                            )

    return {"checks": checks, "write_checks": write_checks}


def _scan_storage(
    buckets: List[str],
    auth_context: AuthContext,
    write_enabled: bool,
    limiter: RateLimiter,
    timeout_seconds: float,
    *,
    proxy: Optional[str] = None,
) -> Dict[str, object]:
    checks = []
    for bucket in buckets:
        list_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
        project_id = _extract_project_id(bucket) or bucket.replace(".appspot.com", "").replace(".firebasestorage.app", "")
        token = auth_context.token_for(project_id) if auth_context.enabled else None

        limiter.wait()
        read_resp = _request("GET", list_url, None, {}, timeout_seconds, proxy=proxy)
        read_error = (read_resp.json() or {}).get("error") if read_resp.status < 400 else read_resp.error
        read_ok = read_resp.status < 400 and not read_error
        read_reason = None
        if read_resp.status == 400 and read_resp.body:
            if b"rules_version" in read_resp.body and b"disallowed" in read_resp.body:
                read_reason = "rules_version_error"
        elif read_resp.status == 412:
            read_reason = "service_account_missing_permissions"
        elif read_resp.status == 404:
            read_reason = "not_found"

        auth_read_ok = None
        auth_read_status = None
        if read_resp.status in (401, 403) and token:
            limiter.wait()
            auth_read_resp = _request(
                "GET",
                list_url,
                None,
                {"Authorization": f"Bearer {token}"},
                timeout_seconds,
                proxy=proxy,
            )
            auth_read_error = (
                (auth_read_resp.json() or {}).get("error")
                if auth_read_resp.status < 400
                else auth_read_resp.error
            )
            auth_read_ok = auth_read_resp.status < 400 and not auth_read_error
            auth_read_status = auth_read_resp.status

        write_ok = False
        write_error = None
        write_status = None
        auth_write_ok = None
        auth_write_status = None
        auth_write_headers = None
        if write_enabled:
            name = "droidhunter-write-check.txt"
            upload_url = (
                f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?"
                + urlencode({"uploadType": "media", "name": name})
            )
            limiter.wait()
            write_resp = _request(
                "POST",
                upload_url,
                b"droidhunter write check",
                {"Content-Type": "text/plain"},
                timeout_seconds,
                proxy=proxy,
            )
            write_error = (write_resp.json() or {}).get("error") if write_resp.status < 400 else write_resp.error
            write_ok = write_resp.status < 400 and not write_error
            write_status = write_resp.status
            if not write_ok and write_resp.status in (401, 403) and token:
                limiter.wait()
                auth_write_headers = {"Content-Type": "text/plain", "Authorization": f"Bearer {token}"}
                auth_write_resp = _request(
                    "POST",
                    upload_url,
                    b"droidhunter write check",
                    auth_write_headers,
                    timeout_seconds,
                    proxy=proxy,
                )
                auth_write_error = (
                    (auth_write_resp.json() or {}).get("error")
                    if auth_write_resp.status < 400
                    else auth_write_resp.error
                )
                auth_write_ok = auth_write_resp.status < 400 and not auth_write_error
                auth_write_status = auth_write_resp.status
            if write_ok:
                delete_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{quote(name)}"
                limiter.wait()
                _request(
                    "DELETE",
                    delete_url,
                    None,
                    {},
                    timeout_seconds,
                    proxy=proxy,
                )
            elif auth_write_ok and auth_write_headers:
                delete_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{quote(name)}"
                limiter.wait()
                _request(
                    "DELETE",
                    delete_url,
                    None,
                    auth_write_headers,
                    timeout_seconds,
                    proxy=proxy,
                )

        checks.append(
            {
                "target": bucket,
                "read": read_ok,
                "read_status": read_resp.status,
                "read_reason": read_reason,
                "auth_read": auth_read_ok,
                "auth_read_status": auth_read_status,
                "write": write_ok if write_enabled else None,
                "write_status": write_status if write_enabled else None,
                "auth_write": auth_write_ok,
                "auth_write_status": auth_write_status,
                "error": write_error or read_error,
            }
        )

    return {"checks": checks}


def _scan_remote_config(
    auth_data: Dict[str, Dict[str, object]],
    limiter: RateLimiter,
    timeout_seconds: float,
    *,
    proxy: Optional[str] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, object]:
    checks: List[Dict[str, object]] = []
    for project_id, config in auth_data.items():
        api_keys = list(config.get("api_keys") or [])
        app_id = config.get("app_id")
        package_name = config.get("package_name")
        cert_sha1_list = list(config.get("cert_sha1_list") or [])
        if config.get("api_key") and config.get("api_key") not in api_keys:
            api_keys.append(config.get("api_key"))
        if not api_keys or not app_id:
            checks.append(
                {
                    "target": project_id,
                    "read": False,
                    "status": 0,
                    "security": "MISSING_CONFIG",
                    "error": "Missing API key or App ID",
                }
            )
            continue

        response = None
        selected_key = None
        selected_cert = None
        for api_key in api_keys:
            url = (
                "https://firebaseremoteconfig.googleapis.com/v1/projects/"
                f"{project_id}/namespaces/firebase:fetch?key={api_key}"
            )
            for cert in cert_sha1_list or [None]:
                headers = {"Content-Type": "application/json"}
                if package_name:
                    headers["X-Android-Package"] = package_name
                if cert:
                    headers["X-Android-Cert"] = cert
                payload = json.dumps({"appId": app_id, "appInstanceId": "PROD"}).encode("utf-8")
                limiter.wait()
                response = _request("POST", url, payload, headers, timeout_seconds, proxy=proxy)
                selected_key = api_key
                selected_cert = cert

                if response.status == 403 and cert and cert != (cert_sha1_list[-1] if cert_sha1_list else None):
                    try:
                        body = response.json() or {}
                        message = (
                            body.get("error", {}).get("message", "")
                            if isinstance(body, dict)
                            else ""
                        )
                        if "Android client application" in message and "are blocked" in message:
                            continue
                    except Exception:
                        pass
                break
            if response and response.status == 200:
                break

        if not response:
            checks.append(
                {
                    "target": project_id,
                    "read": False,
                    "status": 0,
                    "security": "ERROR",
                    "error": "No response",
                }
            )
            continue

        response_text = response.body.decode("utf-8", errors="ignore")
        if response.status == 200:
            if '"state":"NO_TEMPLATE"' in response_text or '"state": "NO_TEMPLATE"' in response_text:
                checks.append(
                    {
                        "target": project_id,
                        "read": False,
                        "status": response.status,
                        "security": "NO_CONFIG",
                        "error": "No Remote Config template",
                        "api_key": selected_key,
                    }
                )
            else:
                saved_file = None
                if output_dir:
                    output_dir.mkdir(parents=True, exist_ok=True)
                    saved_file = output_dir / f"remote_config_{project_id}.json"
                    try:
                        saved_file.write_text(response_text, encoding="utf-8")
                    except Exception:
                        saved_file = None
                checks.append(
                    {
                        "target": project_id,
                        "read": True,
                        "status": response.status,
                        "security": "PUBLIC",
                        "api_key": selected_key,
                        "cert_sha1": selected_cert,
                        "saved_file": str(saved_file) if saved_file else None,
                    }
                )
        elif response.status in (401, 403):
            checks.append(
                {
                    "target": project_id,
                    "read": False,
                    "status": response.status,
                    "security": "PROTECTED",
                    "api_key": selected_key,
                    "error": response_text,
                }
            )
        elif response.status == 404:
            checks.append(
                {
                    "target": project_id,
                    "read": False,
                    "status": response.status,
                    "security": "NOT_FOUND",
                    "api_key": selected_key,
                }
            )
        elif response.status == 429:
            checks.append(
                {
                    "target": project_id,
                    "read": False,
                    "status": response.status,
                    "security": "RATE_LIMITED",
                    "api_key": selected_key,
                }
            )
        else:
            checks.append(
                {
                    "target": project_id,
                    "read": False,
                    "status": response.status,
                    "security": "UNKNOWN",
                    "api_key": selected_key,
                    "error": response_text,
                }
            )

    return {"checks": checks}


def _build_summary(results: Dict[str, object]) -> List[Dict[str, object]]:
    summary: List[Dict[str, object]] = []
    targets = results.get("targets") or {}
    summary.append(
        {
            "title": "Targets",
            "counts": {
                "Project IDs": len(targets.get("project_ids", [])),
                "API Keys": len(targets.get("api_keys", [])),
                "App IDs": len(targets.get("app_ids", [])),
                "Database URLs": len(targets.get("database_urls", [])),
                "Storage Buckets": len(targets.get("storage_buckets", [])),
                "Firestore Collections": len(targets.get("firestore_collections", [])),
                "Packages": len(targets.get("package_names", [])),
                "Certificates": len(targets.get("cert_sha1_list", [])),
            },
        }
    )

    auth = results.get("auth") or {}
    if auth.get("enabled"):
        summary.append(
            {
                "title": "Auth",
                "counts": {"Status": "ok" if auth.get("success") else "failed"},
            }
        )

    services = results.get("services") or {}
    summary.extend(_summarize_service("Realtime Database", services.get("rtdb", {})))
    firestore = services.get("firestore", {})
    summary.extend(_summarize_service("Firestore", firestore, write_checks_key="write_checks"))
    summary.extend(_summarize_service("Storage", services.get("storage", {})))
    if services.get("remote_config"):
        summary.extend(_summarize_service("Remote Config", services.get("remote_config", {})))
    return summary


def _summarize_service(
    title: str, data: Dict[str, object], *, write_checks_key: Optional[str] = None
) -> List[Dict[str, object]]:
    checks = data.get("checks") or []
    readable = sum(1 for c in checks if c.get("read") or c.get("auth_read"))
    errors = sum(1 for c in checks if c.get("error"))
    write_checks = data.get(write_checks_key or "") or []
    if write_checks:
        writable = sum(1 for c in write_checks if c.get("write") or c.get("auth_write"))
    else:
        writable = sum(1 for c in checks if c.get("write") or c.get("auth_write"))
    return [
        {
            "title": title,
            "counts": {
                "Targets": len(checks),
                "Readable": readable,
                "Writable": writable,
                "Errors": errors,
            },
        }
    ]


def _request(
    method: str,
    url: str,
    body: Optional[bytes],
    headers: Dict[str, str],
    timeout_seconds: float,
    *,
    proxy: Optional[str] = None,
) -> HttpResponse:
    request = Request(url, data=body, headers=headers, method=method)
    try:
        if proxy:
            handler = ProxyHandler({"http": proxy, "https": proxy})
            opener = build_opener(handler)
            with opener.open(request, timeout=timeout_seconds) as resp:
                return HttpResponse(status=resp.status, body=resp.read())
        with urlopen(request, timeout=timeout_seconds) as resp:
            return HttpResponse(status=resp.status, body=resp.read())
    except HTTPError as exc:
        return HttpResponse(status=exc.code, body=exc.read(), error=str(exc))
    except URLError as exc:
        return HttpResponse(status=0, body=b"", error=str(exc))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()
