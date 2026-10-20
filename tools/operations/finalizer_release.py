#!/usr/bin/env python3
"""Run the administrator-only finalizer release workflow."""

from tools.operations.finalizer_recovery import main

if __name__ == "__main__":
    raise SystemExit(main())
