"""Cross-request state for the demo backend (contract v2, config-file model).

Single-worker server -> requests serialize; there is NO concurrency to guard, so
there are NO locks, NO tombstones and NO burn-on-read. Everything lives under
``.runtime/`` (git-ignored, wiped at startup):

* ``config/{id}.json``       - the canonical SDK config file the scenario runs OFF
  (written by ``POST /api/scenarios/{id}/config`` from the browser settings; NOT
  TTL-swept).
* ``config/{id}.meta.json``  - demo-only run parameters that are not SDK Config
  fields (published flow id, connection id, fixture choice).
* ``config/keys/<sha1>.pem`` - the service private-key file the config references
  by path (mode 0600).
* ``runs/{runId}.json``      - the platform flowRunId + accumulating step log for
  one demo run.

Config files persist across runs (they are configuration, not runs) and are
removed only by a Clear or the startup wipe. Run files are written via
write-temp + atomic rename (crash hygiene only) and removed by their 30-minute
TTL (lazy sweep on any request, which also collects orphaned ``*.tmp`` files),
by Clear, or by the startup wipe.
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
_KEY_FIELDS = ("service_private_key",)


class Runtime:
    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self.runtime_dir = os.path.join(base_dir, ".runtime")
        self.runs_dir = os.path.join(self.runtime_dir, "runs")
        self.config_dir = os.path.join(self.runtime_dir, "config")
        self.config_keys_dir = os.path.join(self.config_dir, "keys")

    # ── directories ─────────────────────────────────────────────────────────

    def ensure_dirs(self) -> None:
        for d in (self.runtime_dir, self.runs_dir, self.config_dir, self.config_keys_dir):
            os.makedirs(d, mode=0o700, exist_ok=True)

    def wipe_all(self) -> None:
        """Startup wipe: remove ALL runtime state, then recreate the empty tree."""
        shutil.rmtree(self.runtime_dir, ignore_errors=True)
        self.ensure_dirs()

    # ── lazy TTL sweep ──────────────────────────────────────────────────────

    def sweep(self) -> None:
        """Remove expired run files + orphaned ``*.tmp`` (every request). Configs are exempt."""
        now = time.time()
        if not os.path.isdir(self.runs_dir):
            return
        for name in os.listdir(self.runs_dir):
            path = os.path.join(self.runs_dir, name)
            if name.endswith(".tmp"):
                _unlink(path)
            elif name.endswith(".json") and (now - _mtime(path)) > TTL:
                _unlink(path)

    # ── config files ────────────────────────────────────────────────────────

    def config_path_for(self, store_id: int) -> str:
        return os.path.join(self.config_dir, f"{store_id}.json")

    def meta_path_for(self, store_id: int) -> str:
        return os.path.join(self.config_dir, f"{store_id}.meta.json")

    def has_config(self, store_id: int) -> bool:
        return os.path.isfile(self.config_path_for(store_id))

    def write_config(self, store_id: int, config: Dict[str, Any]) -> str:
        """Write the scenario's canonical SDK config file. Returns the RELATIVE path."""
        self.ensure_dirs()
        _atomic_write(self.config_path_for(store_id), _dumps(config))
        return f".runtime/config/{store_id}.json"

    def write_config_meta(self, store_id: int, meta: Dict[str, Any]) -> None:
        self.ensure_dirs()
        _atomic_write(self.meta_path_for(store_id), _dumps(meta))

    def read_config_meta(self, store_id: int) -> Dict[str, Any]:
        return _read_json(self.meta_path_for(store_id)) or {}

    def load_config(self, store_id: int) -> Dict[str, Any]:
        return _read_json(self.config_path_for(store_id)) or {}

    def materialize_config_key(self, pem: str) -> str:
        """Write a browser-sent PEM to ``config/keys/<sha1>.pem`` (0600), return its ABSOLUTE path.

        Content-addressed: identical PEM reuses the same file. Removed only by
        Clear / startup wipe.
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

    # ── clear ─────────────────────────────────────────────────────────────────

    def clear_scenario(self, store_id: int) -> None:
        """Delete the scenario's run files + config + meta, then GC unreferenced key PEMs."""
        for name in _listdir(self.runs_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.runs_dir, name)
            data = _read_json(path)
            if data and int(data.get("scenario") or 0) == store_id:
                _unlink(path)
        _unlink(self.config_path_for(store_id))
        _unlink(self.meta_path_for(store_id))
        self._gc_config_keys()

    def clear_all(self) -> None:
        """Global clear: wipe all run files + the entire config tree."""
        for name in _listdir(self.runs_dir):
            _unlink(os.path.join(self.runs_dir, name))
        shutil.rmtree(self.config_dir, ignore_errors=True)
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
