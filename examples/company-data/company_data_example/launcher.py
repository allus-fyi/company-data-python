"""Serve the company-data example (contract v3) under a single-worker stdlib server.

Runs INSIDE the example's venv (deps installed), so ``allus_company_data`` imports
cleanly. Steps mirror the PHP reference ``bin/start.php``:

1. wipe ``.runtime/`` (fresh state each boot),
2. on a missing/unverified bundle: fetch the pinned frontend release
   (``frontend.lock``), VERIFY sha256, unpack to ``.frontend/<tag>/`` (a present,
   checksum-verified bundle is a cache hit — nothing is re-fetched),
3. assert the bundle's ``contract.json`` version == the backend's implemented
   contractVersion — refuse loudly on a mismatch or checksum failure,
4. refuse a busy port with a clear message,
5. serve with ``http.server.HTTPServer`` — ONE worker (serves one request at a
   time; no threading), so requests serialize (incl. the public POST /webhook).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sys
import tarfile
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from .runtime import Runtime
from .server import CONTRACT_VERSION, Server

RELEASE_BASE = "https://github.com/allme-sdk/example-test-suite/releases/download"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fail(msg: str) -> "None":
    sys.stderr.write(f"\nERROR: {msg}\n")
    sys.exit(1)


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        return version("allus-company-data")
    except Exception:  # pragma: no cover
        return "unknown"


def _read_lock() -> dict:
    try:
        with open(os.path.join(BASE_DIR, "frontend.lock"), "r", encoding="utf-8") as fh:
            lock = json.load(fh)
    except (OSError, ValueError):
        lock = None
    if not isinstance(lock, dict) or "tag" not in lock or "sha256" not in lock:
        _fail('frontend.lock missing or malformed (need {"tag","sha256"}).')
    return lock


def _ensure_frontend(lock: dict) -> str:
    tag = str(lock["tag"])
    want_sha = str(lock["sha256"]).lower()
    frontend = os.path.join(BASE_DIR, ".frontend", tag)  # per-tag cache dir

    mark = ""
    try:
        with open(os.path.join(frontend, ".sha"), "r", encoding="utf-8") as fh:
            mark = fh.read().strip().lower()
    except OSError:
        pass
    cache_valid = (
        os.path.isfile(os.path.join(frontend, "index.html"))
        and os.path.isfile(os.path.join(frontend, "contract.json"))
        and mark != ""
        and mark == want_sha
    )
    if cache_valid:
        sys.stderr.write(f"frontend {tag} present + checksum-verified (cache hit)\n")
        return frontend

    url = f"{RELEASE_BASE}/{tag}/dist.tar.gz"
    sys.stderr.write(f"fetching frontend {tag} -> {url}\n")
    tmp = os.path.join(BASE_DIR, ".frontend.download.tar.gz")
    try:
        with urllib.request.urlopen(url) as resp, open(tmp, "wb") as out:  # noqa: S310
            shutil.copyfileobj(resp, out)
    except Exception as exc:  # noqa: BLE001
        _fail(
            f"could not download the pinned frontend release ({url}): {exc}\n"
            f"If the release does not exist yet, seed it manually: build the frontend, then\n"
            f"  mkdir -p {frontend} && tar -xzf dist.tar.gz -C {frontend}\n"
            f"  printf %s {want_sha} > {os.path.join(frontend, '.sha')}"
        )

    got_sha = _sha256_file(tmp)
    if got_sha != want_sha:
        os.unlink(tmp)
        _fail(
            "frontend checksum MISMATCH.\n"
            f"  expected {want_sha}\n  got      {got_sha}\n"
            "Refusing to serve an unverified bundle. Fix frontend.lock or re-download."
        )

    shutil.rmtree(frontend, ignore_errors=True)
    os.makedirs(frontend, exist_ok=True)
    with tarfile.open(tmp, "r:gz") as tar:
        _safe_extract(tar, frontend)
    os.unlink(tmp)
    if not os.path.isfile(os.path.join(frontend, "index.html")):
        _fail("failed to unpack the frontend bundle.")
    with open(os.path.join(frontend, ".sha"), "w", encoding="utf-8") as fh:
        fh.write(want_sha)
    sys.stderr.write(f"frontend {tag} verified + unpacked -> {frontend}\n")
    return frontend


def _contract_guard(frontend: str) -> None:
    try:
        with open(os.path.join(frontend, "contract.json"), "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, ValueError):
        bundle = {}
    bundle_version = bundle.get("contractVersion") if isinstance(bundle, dict) else None
    if bundle_version != CONTRACT_VERSION:
        _fail(
            f"contract mismatch: bundle contractVersion={bundle_version!r}, "
            f"backend implements {CONTRACT_VERSION}.\n"
            "Bump the frontend.lock pin to a release whose contract.json matches, "
            "or update the backend."
        )


def _make_handler(server: Server):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {k: v for k, v in self.headers.items()}
            resp = server.dispatch(self.command, self.path, body, headers)
            self.send_response(resp.status)
            for name, value in resp.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            if resp.body:
                self.wfile.write(resp.body)

        def do_GET(self) -> None:  # noqa: N802
            self._handle()

        def do_POST(self) -> None:  # noqa: N802
            self._handle()

        def log_message(self, fmt: str, *args) -> None:  # quieter logs
            sys.stderr.write("  " + (fmt % args) + "\n")

    return Handler


def main() -> None:
    os.chdir(BASE_DIR)
    sys.stderr.write("company-data example (python) — starting up\n")

    Runtime(BASE_DIR).wipe_all()  # fresh runtime state

    lock = _read_lock()
    frontend = _ensure_frontend(lock)
    _contract_guard(frontend)

    port = int(os.environ.get("PORT") or 8091)
    # Refuse a busy port with a clear message.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("localhost", port))
    except OSError:
        _fail(
            f"port {port} is busy. Set PORT=<n> to use another port "
            "(one browser origin is shared across SDK examples, so only one runs at a time)."
        )
    finally:
        probe.close()

    rt = Runtime(BASE_DIR)
    srv = Server(rt, frontend, _sdk_version())
    httpd = HTTPServer(("localhost", port), _make_handler(srv))
    sys.stderr.write(f"serving http://localhost:{port}  (Ctrl-C to stop)\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
        httpd.server_close()


# ── stdlib helpers ────────────────────────────────────────────────────────────


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    dest_root = os.path.realpath(dest)
    for member in tar.getmembers():
        target = os.path.realpath(os.path.join(dest, member.name))
        if not target.startswith(dest_root):
            _fail(f"refusing unsafe tar entry: {member.name}")
    tar.extractall(dest)  # noqa: S202 — members validated above
