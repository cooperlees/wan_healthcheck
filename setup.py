"""Env-gated mypyc build: WAN_HEALTHCHECK_MYPYC=1 compiles the module to a C
extension (used on the router); unset installs pure Python (used by CI tests)."""

import os

from setuptools import setup

if os.environ.get("WAN_HEALTHCHECK_MYPYC") == "1":
    from mypyc.build import mypycify

    setup(ext_modules=mypycify(["wan_healthcheck.py"]))
else:
    setup()
