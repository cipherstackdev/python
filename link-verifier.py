#!/usr/bin/env python3
"""Check links from files or command-line input."""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests


URL_RE = re.compile(r"https?://[^\s<>)\"']+")


@dataclass(frozen=True)
class LinkResult:
    url: str
    ok: bool
    status_code: int | None
    status: str
    seconds: float | None
    final_url: str | None = None
    error: str | None = None


def extract_urls(text: str) -> set[str]:
    return {match.rstrip(".,;:") for match in URL_RE.findall(text)}


def urls_from_file(path: Path) -> set[str]:
    try:
        return extract_urls(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return extract_urls(path.read_text(encoding="utf-8", errors="ignore"))


def check_url(session: requests.Session, url: str, timeout: int) -> LinkResult:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return LinkResult(url, False, None, "invalid", None, error="Invalid URL")

    started = time.monotonic()
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True)
        if response.status_code in {405, 403}:
            response = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
        seconds = round(time.monotonic() - started, 2)
        ok = response.status_code < 400
        return LinkResult(
            url=url,
            ok=ok,
            status_code=response.status_code,
            status="ok" if ok else "failed",
            seconds=seconds,
            final_url=response.url,
        )
    except requests.exceptions.Timeout:
        return LinkResult(url, False, None, "timeout", None, error=f"Timed out after {timeout}s")
    except requests.exceptions.RequestException as exc:
        return LinkResult(url, False, None, "error", None, error=str(exc))


def collect_urls(args: argparse.Namespace) -> list[str]:
    urls: set[str] = set(args.url or [])

    for file_arg in args.file or []:
        urls.update(urls_from_file(Path(file_arg)))

    for item in args.inputs:
        if item.startswith(("http://", "https://")):
            urls.add(item)
        else:
            urls.update(urls_from_file(Path(item)))

    return sorted(urls)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check URLs from files or command-line input.")
    parser.add_argument("inputs", nargs="*", help="URLs or files to scan")
    parser.add_argument("-f", "--file", action="append", help="File to extract URLs from")
    parser.add_argument("-u", "--url", action="append", help="URL to check")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Concurrent workers")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show successful links too")
    args = parser.parse_args()

    urls = collect_urls(args)
    if not urls:
        parser.print_help()
        return 2

    session = requests.Session()
    session.headers.update({"User-Agent": "CipherStack-LinkVerifier/1.0"})

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_url, session, url, args.timeout) for url in urls]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]

    failed = sorted((result for result in results if not result.ok), key=lambda result: result.url)
    passed = sorted((result for result in results if result.ok), key=lambda result: result.url)

    print(f"Checked: {len(results)}")
    print(f"Passed:  {len(passed)}")
    print(f"Failed:  {len(failed)}")

    if args.verbose and passed:
        print("\nPassed")
        for result in passed:
            redirect = f" -> {result.final_url}" if result.final_url and result.final_url != result.url else ""
            print(f"[{result.status_code}] {result.url}{redirect} ({result.seconds}s)")

    if failed:
        print("\nFailed")
        for result in failed:
            status = result.status_code if result.status_code is not None else result.status
            detail = f" - {result.error}" if result.error else ""
            print(f"[{status}] {result.url}{detail}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
