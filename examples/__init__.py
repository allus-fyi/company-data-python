"""The runnable allus SDK example suite, shipped inside the installed package.

This file exists so the top-level ``examples/`` tree can be mapped into the wheel as
``allus_company_data.examples`` (see pyproject.toml). The suite itself is an ordinary
standalone project — run it from the directory this package resolves to
(``python bin/start.py``); nothing here is imported by the SDK, and the SDK never
depends on the suite's own dependencies.
"""
