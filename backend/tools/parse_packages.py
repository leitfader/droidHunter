#!/usr/bin/env python3
"""Package Name Parser - Extracts and counts unique package names from a file,
then scrapes Google Play Store for contact emails and download counts.

Dependencies:
    pip install requests beautifulsoup4

Usage: python parse_packages.py <input_file>

Example format expected in file:
"Project ID: openfire-base (from package: com.openfire.base)"

Output example:
  5 - com.openfire.base [10M+]
      Email: support@example.com
"""

import re
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup


def parse_package_names(file_path: str) -> Counter:
    """Parse package names from a file and return unique counts."""
    pattern = r"\(from package:\s+([^)]+)\)"
    package_names = []

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as file:
            for line in file:
                matches = re.findall(pattern, line)
                for match in matches:
                    package_name = match.strip()
                    if package_name:
                        package_names.append(package_name)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return Counter()
    except Exception as exc:
        print(f"Error reading file: {exc}")
        return Counter()

    return Counter(package_names)


def scrape_info_from_play_store(package_name: str):
    """Scrape email address and download count from Google Play Store page."""
    url = f"https://play.google.com/store/apps/details?id={quote(package_name)}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
    }

    try:
        print(f"  Scraping: {package_name}...", end=" ")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        email = None
        download_count = None

        mailto_links = soup.find_all("a", href=re.compile(r"^mailto:"))
        if mailto_links:
            href = mailto_links[0].get("href")
            email_match = re.search(r"mailto:([^?&]+)", href)
            if email_match:
                email = email_match.group(1)

        clm7o_divs = soup.find_all("div", class_="ClM7O")
        for div in clm7o_divs:
            text = div.get_text(strip=True)
            if re.search(r"\d+.*(?:mln|tys|k|\+|million|thousand)", text.lower()):
                download_count = text
                break

        results = []
        if email:
            results.append(f"Email: {email}")
        if download_count:
            results.append(f"Downloads: {download_count}")

        if results:
            print(f"OK - {', '.join(results)}")
        else:
            print("No info found")

        return email, download_count

    except requests.exceptions.RequestException as exc:
        print(f"Error: {exc}")
        return None, None
    except Exception as exc:
        print(f"Parse error: {exc}")
        return None, None


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python parse_packages.py <input_file>")
        print("\nExample:")
        print("python parse_packages.py results.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    if not Path(input_file).exists():
        print(f"Error: File '{input_file}' does not exist.")
        sys.exit(1)

    print(f"Parsing package names from: {input_file}")
    print("-" * 50)

    package_counts = parse_package_names(input_file)
    if not package_counts:
        print("No package names found in the file.")
        return

    print(f"Found {len(package_counts)} unique package names:\n")

    sorted_packages = sorted(package_counts.items(), key=lambda x: (-x[1], x[0]))
    for package_name, count in sorted_packages:
        print(f"{count:3d} - {package_name}")

    print(f"\nTotal unique packages: {len(package_counts)}")
    print(f"Total occurrences: {sum(package_counts.values())}")

    print("\n" + "=" * 60)
    print("SCRAPING INFO FROM GOOGLE PLAY STORE")
    print("=" * 60)

    package_info = {}
    for i, (package_name, count) in enumerate(sorted_packages, 1):
        print(f"\n[{i}/{len(sorted_packages)}]", end=" ")
        email, download_count = scrape_info_from_play_store(package_name)
        package_info[package_name] = {"email": email, "downloads": download_count}
        if i < len(sorted_packages):
            time.sleep(1)

    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    for package_name, count in sorted_packages:
        info = package_info.get(package_name, {})
        email = info.get("email")
        downloads = info.get("downloads")

        package_line = f"{count:3d} - {package_name}"
        if downloads:
            package_line += f" [{downloads}]"
        print(package_line)
        if email:
            print(f"    Email: {email}")


if __name__ == "__main__":
    main()
