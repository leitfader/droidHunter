import re
from pathlib import Path
from typing import Dict, List, Tuple


SUMMARY_HEADER_RE = re.compile(r"^\[.*?\]\s+SCAN SUMMARY\s+(.+)$")
ALT_SUMMARY_HEADER_RE = re.compile(r"^SCAN SUMMARY\s+(.+)$")
SECTION_DIVIDER_RE = re.compile(r"^=+$")
KEY_VALUE_RE = re.compile(r"^([^:]+):\s*(.+)$")


def parse_summary_blocks(text: str) -> List[Dict[str, object]]:
    lines = text.splitlines()
    summaries: List[Dict[str, object]] = []
    current_title = None
    current_counts: Dict[str, str] = {}
    in_summary = False

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = SUMMARY_HEADER_RE.match(line) or ALT_SUMMARY_HEADER_RE.match(line)
        if match:
            if current_title and current_counts:
                summaries.append({"title": current_title, "counts": current_counts})
            current_title = match.group(1).strip()
            current_counts = {}
            in_summary = True
            continue

        if in_summary and SECTION_DIVIDER_RE.match(line):
            continue

        if in_summary:
            kv = KEY_VALUE_RE.match(line)
            if kv:
                key = kv.group(1).strip()
                value = kv.group(2).strip()
                current_counts[key] = value
                continue
            if line.startswith("[!]"):
                current_counts.setdefault("warnings", "")
                current_counts["warnings"] = (current_counts["warnings"] + " " + line).strip()
                continue

        if in_summary and line.startswith("====="):
            continue

    if current_title and current_counts:
        summaries.append({"title": current_title, "counts": current_counts})

    return summaries


def collect_output_files(results_dir: Path) -> List[Dict[str, str]]:
    files = []
    for path in sorted(results_dir.glob("*")):
        if path.is_file():
            files.append({"name": path.name, "path": str(path)})
        elif path.is_dir():
            for nested in sorted(path.rglob("*")):
                if nested.is_file():
                    files.append({"name": f"{path.name}/{nested.name}", "path": str(nested)})
    return files


def find_latest_results_dir(output_root: Path) -> Tuple[Path, List[Path]]:
    if not output_root.exists():
        return output_root, []

    candidates = sorted(
        [p for p in output_root.glob("*_results") if p.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return (candidates[0] if candidates else output_root), candidates
