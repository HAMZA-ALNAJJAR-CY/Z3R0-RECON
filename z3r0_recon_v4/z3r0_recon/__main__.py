"""Allows running as: python3 -m z3r0_recon [doctor]"""
import sys

if len(sys.argv) > 1 and sys.argv[1] == "doctor":
    from .core.doctor import run_doctor
    sys.exit(run_doctor())

from .cli import main

if __name__ == "__main__":
    main()
