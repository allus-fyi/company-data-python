"""Serve the whole example suite (contract v3) under a single-worker stdlib server.

ONE server, ONE port, all three scenario families. Runs INSIDE the example's venv
(deps installed), so ``allus_company_data`` + ``authlib`` import cleanly. Steps:

1. wipe ``.runtime/`` (fresh state each boot),
2. on a missing/unverified bundle: fetch the pinned frontend release
   (``frontend.lock``), VERIFY sha256, unpack to ``.frontend/<tag>/`` (a present,
   checksum-verified bundle is a cache hit — nothing is re-fetched),
3. assert the bundle's ``contract.json`` version == the backend's implemented
   contractVersion — refuse loudly on a mismatch or checksum failure,
4. refuse a busy port with a clear message,
5. serve with ``http.server.HTTPServer`` — ONE worker (serves one request at a time;
   no threading), so requests serialize (incl. the public POST /webhook) — bound to
   ALL interfaces (``0.0.0.0``) so a phone on the same network can reach it, printing
   every URL it is reachable on (#553).
"""

from __future__ import annotations

import ctypes
import ctypes.util
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
    sys.stderr.write("allus example suite (python) — starting up\n")

    Runtime(BASE_DIR).wipe_all()  # fresh runtime state

    lock = _read_lock()
    frontend = _ensure_frontend(lock)
    _contract_guard(frontend)

    port = int(os.environ.get("PORT") or 8091)
    # Refuse a busy port with a clear message — probe the SAME address the server binds
    # (all interfaces), not just loopback.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("0.0.0.0", port))
    except OSError:
        _fail(
            f"port {port} is busy. Set PORT=<n> to use another port "
            "(one browser origin is shared across SDK examples, so only one runs at a time)."
        )
    finally:
        probe.close()

    rt = Runtime(BASE_DIR)
    srv = Server(rt, frontend, _sdk_version())
    # ALL interfaces, so a phone on the same network can reach it (#553).
    httpd = HTTPServer(("0.0.0.0", port), _make_handler(srv))
    _print_reachable_urls(port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
        httpd.server_close()


# ── stdlib helpers ────────────────────────────────────────────────────────────


def _print_reachable_urls(port: int) -> None:
    """Announce every URL the server is reachable on (#553).

    The server binds all interfaces, so a phone on the same network can reach it — but
    only if the person holding the phone knows which address to type. Print the loopback
    URL AND every non-loopback IPv4 address of this host, plus the plain warning that this
    is now open to the local network.
    """
    w = sys.stderr.write
    w(f"serving on ALL interfaces, port {port}  (all three scenario families; Ctrl-C to stop)\n")
    w(f"  on this machine:  http://localhost:{port}\n")
    lan = _lan_addresses()
    if not lan:
        w("  on this network:  (no non-loopback IPv4 address found — is this machine on a network?)\n")
    else:
        for i, addr in enumerate(lan):
            label = "  on this network:  " if i == 0 else "                    "
            w(f"{label}http://{addr}:{port}\n")
    w("  NOTE: anyone on your network can now reach this demo, and its setup panels accept and\n")
    w("        store real credentials under .runtime/config/ — OAuth and data-client secrets,\n")
    w("        private-key PEMs and their passphrases, and webhook signing secrets. It is a local\n")
    w("        developer example, not a hardened service: run it only on a network you trust, and\n")
    w("        only with sandbox credentials.\n")


def _lan_addresses() -> list:
    """EVERY non-loopback, non-link-local IPv4 address of this host, one per interface.

    IPv4 only — an IPv6 literal is not what anyone types into a phone.

    This ENUMERATES the interfaces (POSIX ``getifaddrs(3)`` via ctypes), which is what the
    other five SDKs get from their platform libraries (``net_get_interfaces``,
    ``os.networkInterfaces``, ``net.Interfaces``, ``NetworkInterface.*``). Python's stdlib
    has no interface API, and the two obvious substitutes are both WRONG here: a UDP route
    probe returns the ONE source address for one destination, and ``getaddrinfo(gethostname())``
    returns whatever the hostname resolves to. On a laptop with Wi-Fi plus a VPN or a docker
    bridge each yields a single address — and not necessarily the one the phone can reach.
    """
    found: list = []

    def add(addr: str) -> None:
        if not addr or addr.startswith("127.") or addr.startswith("169.254."):
            return
        if addr not in found:
            found.append(addr)

    for addr in _getifaddrs_ipv4():
        add(addr)
    if found:
        return found

    # Fallback for a platform without getifaddrs (Windows): the single-address substitutes.
    # Incomplete by construction — which is why it runs only when enumeration is unavailable.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # TEST-NET-1 (RFC 5737), never routed anywhere real
        add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except OSError:
        pass

    return found


class _IfAddrs(ctypes.Structure):
    """POSIX ``struct ifaddrs`` — same field order on Linux and macOS/BSD."""


_IfAddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(_IfAddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.c_void_p),
    ("ifa_netmask", ctypes.c_void_p),
    ("ifa_dstaddr", ctypes.c_void_p),
    ("ifa_data", ctypes.c_void_p),
]

_IFF_UP = 0x1
_IFF_LOOPBACK = 0x8


def _getifaddrs_ipv4() -> list:
    """Walk ``getifaddrs(3)`` and return the IPv4 address of every UP, non-loopback interface.

    ``sockaddr`` differs in its first two bytes between the two POSIX families — Linux has a
    16-bit ``sa_family``, macOS/BSD a 1-byte ``sa_len`` then a 1-byte ``sa_family`` — so the
    family is read per-platform. The IPv4 address itself sits at offset 4 in both.
    Returns ``[]`` (never raises) when the C library or the symbol is unavailable.
    """
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        getifaddrs = libc.getifaddrs
        freeifaddrs = libc.freeifaddrs
    except (OSError, AttributeError):
        return []

    getifaddrs.restype = ctypes.c_int
    getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_IfAddrs))]
    freeifaddrs.argtypes = [ctypes.POINTER(_IfAddrs)]

    head = ctypes.POINTER(_IfAddrs)()
    if getifaddrs(ctypes.byref(head)) != 0:
        return []

    bsd_sockaddr = sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))
    out: list = []
    try:
        node = head
        while node:
            entry = node.contents
            node = entry.ifa_next
            if not entry.ifa_addr:
                continue
            if not (entry.ifa_flags & _IFF_UP) or (entry.ifa_flags & _IFF_LOOPBACK):
                continue
            raw = ctypes.string_at(entry.ifa_addr, 8)  # sockaddr_in's first 8 bytes
            family = raw[1] if bsd_sockaddr else int.from_bytes(raw[0:2], sys.byteorder)
            if family != socket.AF_INET:
                continue
            out.append(socket.inet_ntoa(raw[4:8]))
    finally:
        freeifaddrs(head)
    return out


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
