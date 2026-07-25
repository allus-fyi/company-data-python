#!/usr/bin/env python3
"""One-command launcher for the Python company-data example.

    python bin/start.py            # (or: PORT=9000 python bin/start.py)

Stdlib-only bootstrapper: it creates a local ``.venv`` and installs the example's
own dependencies (the local ``allus-company-data`` SDK, editable) on first run,
then hands off to ``company_data_example`` running under that venv. A present venv
is reused (nothing is reinstalled).

The example's deps live in ``requirements.txt`` — its OWN manifest, separate from
the published SDK package (the SDK's ``pyproject.toml`` packages only ``src/``, so
nothing here leaks into the SDK distribution).

The allus-company-data SDK requires Python >= 3.11, so invoke this launcher with a
3.11+ interpreter (the venv inherits that interpreter).
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
        # cwd=BASE so the requirements file's relative editable path (-e ../..) resolves
        # to the SDK root regardless of where the user invoked this launcher from.
        subprocess.check_call(
            [py, "-m", "pip", "install", "-q", "-r", "requirements.txt"], cwd=BASE
        )

    # Hand off to the server under the venv interpreter. PYTHONPATH exposes the
    # example package (company_data_example) regardless of the caller's cwd.
    env = dict(os.environ, PYTHONPATH=BASE)
    os.execve(py, [py, "-m", "company_data_example", *sys.argv[1:]], env)


if __name__ == "__main__":
    main()
