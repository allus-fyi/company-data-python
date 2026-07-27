#!/usr/bin/env python3
"""One-command launcher for the Python allus SDK example suite.

    python bin/start.py            # (or: PORT=9000 python bin/start.py)

Stdlib-only bootstrapper: it creates a local ``.venv`` and installs the examples'
own dependencies (the local ``allus-company-data`` SDK, editable, + Authlib for the
OIDC identity scenarios) on first run, then hands off to ``allus_examples`` running
under that venv — ONE server serving all three scenario families on one port. A
present venv is reused (nothing is reinstalled).

The examples' third-party deps live in ``requirements.txt`` — their OWN manifest, so
Authlib never becomes a dependency OF the SDK distribution. Since #493 the example
SOURCE does ship inside the installed ``allus-company-data`` artifact (mapped in as
``allus_company_data.examples``): the suite stays a separate runnable project, it is
just carried along by the parent package rather than published on its own. That is why
the SDK itself is installed by context here — see ``_sdk_requirement()``.

The allus-company-data SDK requires Python >= 3.11, so invoke this launcher with a
3.11+ interpreter (the venv inherits that interpreter).
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# One level up from the examples project: the SDK project root in a checkout, or the
# installed package directory that CONTAINS this example when it ships inside the wheel.
SDK_ROOT = os.path.dirname(BASE)


def _sdk_requirement():
    """How to install the SDK, decided by where this suite is actually running (#493).

    Since #493 the example SOURCE ships inside the installed allus-company-data
    artifact, so this launcher runs in two very different places:

    * a repository CHECKOUT — ``..`` is the SDK project root (it has a
      ``pyproject.toml``), so install it EDITABLE and the examples exercise the working
      tree, exactly as before;
    * an INSTALLED package — ``..`` is inside site-packages, which is NOT a project
      root, so an ``-e ..`` line in requirements.txt could never resolve and the
      launcher died trying to editable-install a project that does not exist. Install
      the SAME version that shipped this copy instead, read from the installed
      distribution's own metadata, so the examples always run against the SDK they
      came with.
    """
    if os.path.exists(os.path.join(SDK_ROOT, "pyproject.toml")):
        return ["-e", SDK_ROOT]
    try:
        from importlib.metadata import version

        return ["allus-company-data==" + version("allus-company-data")]
    except Exception:
        # Metadata unreadable (an unusual install layout) — fall back to the latest
        # release rather than failing outright.
        return ["allus-company-data"]


def _venv_python(venv_dir: str) -> str:
    if os.name == "nt":  # pragma: no cover
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def main() -> None:
    venv_dir = os.path.join(BASE, ".venv")
    py = _venv_python(venv_dir)

    if not os.path.exists(py):
        sys.stderr.write("creating venv + installing dependencies…\n")
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        subprocess.check_call([py, "-m", "pip", "install", "-q", "--upgrade", "pip"])
        # The examples' own third-party deps. cwd=BASE so the relative path resolves
        # regardless of where the user invoked this launcher from.
        subprocess.check_call(
            [py, "-m", "pip", "install", "-q", "-r", "requirements.txt"], cwd=BASE
        )
        # The SDK itself, resolved by context — see _sdk_requirement() (#493).
        subprocess.check_call(
            [py, "-m", "pip", "install", "-q", *_sdk_requirement()], cwd=BASE
        )

    # Hand off to the server under the venv interpreter. PYTHONPATH exposes the
    # example package (allus_examples) regardless of the caller's cwd.
    env = dict(os.environ, PYTHONPATH=BASE)
    os.execve(py, [py, "-m", "allus_examples", *sys.argv[1:]], env)


if __name__ == "__main__":
    main()
