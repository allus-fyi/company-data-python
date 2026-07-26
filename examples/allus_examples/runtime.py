"""Cross-request state for the single-server example suite (config-file model).

ONE ``.runtime/`` tree backs all three scenario families (identity, flow,
company-data) — the single-worker server serialises every request, so there is NO
concurrency to guard: NO locks, NO tombstones, NO burn-on-read. Everything lives
under ``.runtime/`` (git-ignored, wiped at startup):

* ``config/{key}.json``      - the canonical SDK config file a scenario runs OFF
  (written by ``POST /api/scenarios/{id}/config`` from the browser settings; NOT
  TTL-swept). ``{key}`` is a filesystem-safe token unique across families
  (identity ``1``..``8``, flow ``flow_run``, company-data ``companydata_read`` …),
  so the three families never collide in the shared tree.
* ``config/{key}.meta.json`` - demo-only run parameters that are not SDK Config
  fields (authorize_base, one_time claims, share_code, context, flow id, …).
* ``config/keys/<sha1>.pem`` - the private-key file(s) a config references by path
  (mode 0600); content-addressed, so scenarios sharing a key share the file.
* ``runs/{runId}.json``      - one run's PKCE/state/nonce or accumulated result +
  the ``calls`` trace. The run's ``scenario`` field is the key its family clears by.
* ``webhook-route.json``     - the SINGLE active company-data webhook run
  ``{webhookId, runId}``; a new webhook run supersedes it, TTL/Clear drops it.
* ``cache/``                 - the SDK pump's buffer + dead-letter dir
  (``Config.cache_dir`` -> this path), used by the company-data pump scenarios.

Config files persist across runs (they are configuration, not runs) and are
removed only by a Clear or the startup wipe. Run files are written write-temp +
atomic-rename (crash hygiene) and removed by their 30-minute TTL (lazy sweep on
any request, which also collects orphaned ``*.tmp``), by Clear, or by the wipe.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import time
from typing import Any, Dict, List, Optional

TTL = 1800  # 30-minute run TTL (seconds). Config files are exempt.

_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SID_RE = re.compile(r"[^a-z0-9]+", re.IGNORECASE)
# The union of every family's private-key config fields (unreferenced PEMs are GC'd).
_KEY_FIELDS = ("oauth_private_key", "service_private_key")


class Runtime:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self.runtime_dir = os.path.join(base_dir, ".runtime")
        self.runs_dir = os.path.join(self.runtime_dir, "runs")
        self.config_dir = os.path.join(self.runtime_dir, "config")
        self.config_keys_dir = os.path.join(self.config_dir, "keys")
        # The SDK pump persists its buffer + dead-letters here (Config.cache_dir ->
        # this path), so Clear / the startup wipe removes it too.
        self.cache_dir = os.path.join(self.runtime_dir, "cache")
        self.route_path = os.path.join(self.runtime_dir, "webhook-route.json")

    # ── directories ─────────────────────────────────────────────────────────

    def ensure_dirs(self) -> None:
        for d in (self.runtime_dir, self.runs_dir, self.config_dir, self.config_keys_dir, self.cache_dir):
            os.makedirs(d, mode=0o700, exist_ok=True)

    def wipe_all(self) -> None:
        """Startup wipe: remove ALL runtime state, then recreate the empty tree."""
        shutil.rmtree(self.runtime_dir, ignore_errors=True)
        self.ensure_dirs()

    # ── lazy TTL sweep ──────────────────────────────────────────────────────

    def sweep(self) -> None:
        """Remove expired run files + orphaned ``*.tmp`` (every request). Configs are exempt.

        When the active webhook run expires, its routing record is dropped too (a
        stale record never routes to a burned run)."""
        now = time.time()
        if os.path.isdir(self.runs_dir):
            for name in os.listdir(self.runs_dir):
                path = os.path.join(self.runs_dir, name)
                if name.endswith(".tmp"):
                    _unlink(path)
                elif name.endswith(".json") and (now - _mtime(path)) > TTL:
                    _unlink(path)
        route = self.read_route()
        if route is not None and not os.path.isfile(os.path.join(self.runs_dir, f"{route['runId']}.json")):
            _unlink(self.route_path)

    # ── config files ────────────────────────────────────────────────────────

    @staticmethod
    def sid(key: Any) -> str:
        """Filesystem-safe token for a config key (``companydata:read`` -> ``companydata_read``)."""
        return _SID_RE.sub("_", str(key)).strip("_")

    def config_path_for(self, key: Any) -> str:
        return os.path.join(self.config_dir, f"{self.sid(key)}.json")

    def meta_path_for(self, key: Any) -> str:
        return os.path.join(self.config_dir, f"{self.sid(key)}.meta.json")

    def has_config(self, key: Any) -> bool:
        return os.path.isfile(self.config_path_for(key))

    def write_config(self, key: Any, config: Dict[str, Any]) -> str:
        """Write a scenario's canonical SDK config file. Returns the RELATIVE path."""
        self.ensure_dirs()
        _atomic_write(self.config_path_for(key), _dumps(config))
        return f".runtime/config/{self.sid(key)}.json"

    def write_config_meta(self, key: Any, meta: Dict[str, Any]) -> None:
        self.ensure_dirs()
        _atomic_write(self.meta_path_for(key), _dumps(meta))

    def read_config_meta(self, key: Any) -> Dict[str, Any]:
        return _read_json(self.meta_path_for(key)) or {}

    def load_config(self, key: Any) -> Dict[str, Any]:
        return _read_json(self.config_path_for(key)) or {}

    def materialize_config_key(self, pem: str) -> str:
        """Write a browser-sent PEM to ``config/keys/<sha1>.pem`` (0600), return its ABSOLUTE path.

        Content-addressed: identical PEM reuses the same file, so two scenarios
        sharing a service key share the file. Removed only by Clear / startup wipe.
        """
        self.ensure_dirs()
        digest = hashlib.sha1(pem.encode("utf-8")).hexdigest()
        path = os.path.join(self.config_keys_dir, f"{digest}.pem")
        if not os.path.isfile(path):
            _atomic_write(path, pem, mode=0o600)
        os.chmod(path, 0o600)
        return path

    # ── runs ────────────────────────────────────────────────────────────────

    @staticmethod
    def new_run_id() -> str:
        return secrets.token_hex(16)

    @staticmethod
    def is_run_id(value: str) -> bool:
        return bool(value) and bool(_RUN_ID_RE.match(value))

    def write_run(self, run_id: str, data: Dict[str, Any]) -> None:
        data["runId"] = run_id
        _atomic_write(os.path.join(self.runs_dir, f"{run_id}.json"), _dumps(data))

    def read_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Read a run, honouring the TTL. ``None`` for unknown/expired ids (idempotent reads)."""
        if not self.is_run_id(run_id):
            return None
        path = os.path.join(self.runs_dir, f"{run_id}.json")
        if not os.path.isfile(path):
            return None
        if (time.time() - _mtime(path)) > TTL:
            _unlink(path)
            return None
        return _read_json(path)

    # ── webhook routing record (single active webhook run) ────────────────────

    def write_route(self, webhook_id: str, run_id: str) -> None:
        """Persist the single active webhook route, superseding any prior one."""
        self.ensure_dirs()
        _atomic_write(self.route_path, _dumps({"webhookId": webhook_id, "runId": run_id}))

    def read_route(self) -> Optional[Dict[str, str]]:
        data = _read_json(self.route_path)
        if not data or "webhookId" not in data or "runId" not in data:
            return None
        return {"webhookId": str(data["webhookId"]), "runId": str(data["runId"])}

    def clear_route(self) -> None:
        _unlink(self.route_path)

    def wipe_cache(self) -> None:
        shutil.rmtree(self.cache_dir, ignore_errors=True)
        self.ensure_dirs()

    # ── clear ─────────────────────────────────────────────────────────────────

    def clear_scenario(self, match: Any) -> None:
        """Delete a scenario's run files (runs whose ``scenario`` == ``match``) + its
        config + meta (keyed by ``sid(match)``), then GC unreferenced key PEMs.

        Family-specific extras (the webhook route, the pump cache) are handled by the
        owning family's clear path via :meth:`clear_route` / :meth:`wipe_cache`."""
        target = str(match)
        for name in _listdir(self.runs_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.runs_dir, name)
            data = _read_json(path)
            if data and str(data.get("scenario")) == target:
                _unlink(path)
        _unlink(self.config_path_for(match))
        _unlink(self.meta_path_for(match))
        self._gc_config_keys()

    def clear_all(self) -> None:
        """Global clear: wipe all run files, the config tree, the route + pump cache."""
        for name in _listdir(self.runs_dir):
            _unlink(os.path.join(self.runs_dir, name))
        shutil.rmtree(self.config_dir, ignore_errors=True)
        shutil.rmtree(self.cache_dir, ignore_errors=True)
        self.clear_route()
        self.ensure_dirs()

    def _gc_config_keys(self) -> None:
        referenced = set()
        for name in _listdir(self.config_dir):
            if not name.endswith(".json") or name.endswith(".meta.json"):
                continue
            data = _read_json(os.path.join(self.config_dir, name)) or {}
            for f in _KEY_FIELDS:
                p = data.get(f)
                if isinstance(p, str) and p:
                    referenced.add(p)
        for name in _listdir(self.config_keys_dir):
            if not name.endswith(".pem"):
                continue
            path = os.path.join(self.config_keys_dir, name)
            if path not in referenced:
                _unlink(path)


# ── module helpers ────────────────────────────────────────────────────────────


def _dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2)


def _atomic_write(final_path: str, contents: str, mode: Optional[int] = None) -> None:
    tmp = f"{final_path}.{secrets.token_hex(4)}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(contents)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, final_path)


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _listdir(path: str) -> List[str]:
    try:
        return os.listdir(path)
    except OSError:
        return []


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
