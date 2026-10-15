#!/usr/bin/env python3
"""SentinelForge entry point:  python sf.py scan --url http://localhost:3000"""
import sys

from sentinelforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
