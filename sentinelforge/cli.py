"""Command line interface:  python sf.py scan --url http://localhost:3000 --src ./myapp"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import requests

from . import TAGLINE, __version__
from .config import load_config
from .db import Database
from .lib.allowlist import TargetNotAllowed, check_target
from .lib.context import ScanContext
from .lib.http import SafeClient
from .lib.runner import run_checks
from .models import Status, summarise
from .reports.console import render


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sf", description=f"SentinelForge: {TAGLINE}")
    parser.add_argument("--version", action="version", version=f"SentinelForge {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a local app (running copy and/or source code)")
    scan.add_argument("--url", help="base URL of the running app (must be local or allowlisted)")
    scan.add_argument("--src", help="path to the app's source code (read-only)")
    scan.add_argument("--config", help="path to config.yaml (default: ./config.yaml if present)")
    scan.add_argument("--db", help="SQLite file for scan history (default from config)")
    return parser


def cmd_scan(args) -> int:
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"❌ Could not read config: {exc}", file=sys.stderr)
        return 2

    src = Path(args.src).resolve() if args.src else None
    # --src alone means source-only. The config URL is only a fallback when neither flag is given.
    url = args.url or (None if src else config["target"].get("base_url"))
    extra_hosts = config["target"]["allowed_hosts"]

    if not url and not src:
        print("❌ Nothing to scan. Give --url and/or --src (or set target.base_url in config.yaml).",
              file=sys.stderr)
        return 2
    if src and not src.is_dir():
        print(f"❌ --src '{args.src}' is not a directory.", file=sys.stderr)
        return 2

    # Safety gate: runs before anything is created or sent.
    if url:
        try:
            check_target(url, extra_hosts)
        except TargetNotAllowed as exc:
            print(f"❌ Refusing to scan: {exc}", file=sys.stderr)
            return 2

    print(f"SentinelForge {__version__}: {TAGLINE}")
    print(f"Target : {url or '(none, source only)'}")
    print(f"Source : {src or '(none, live only)'}")
    print()

    client = SafeClient(url, extra_hosts, config["http"]["timeout"]) if url else None
    if client is not None:  # preflight: an unreachable target must not look like a clean scan
        try:
            client.get("/")
        except requests.RequestException as exc:
            print(f"❌ Target not reachable at {url}: {type(exc).__name__}. "
                  "Is the app running?", file=sys.stderr)
            return 2

    db = Database(args.db or config["storage"]["db_path"])
    scan_id = db.start_scan(url, str(src) if src else None, __version__)
    try:
        ctx = ScanContext(url=url, src=src, config=config, http=client)
        try:
            findings = run_checks(ctx, config)
        except TargetNotAllowed as exc:
            db.finish_scan(scan_id, {}, status="ABORTED")
            print(f"❌ Scan aborted by safety rule: {exc}", file=sys.stderr)
            return 2

        for finding in findings:
            db.save_finding(scan_id, finding)
        db.finish_scan(scan_id, summarise(findings))
        print(render(findings, scan_id))
        return 1 if any(f.status is Status.FAIL for f in findings) else 0
    except KeyboardInterrupt:  # kill switch: stop cleanly, keep the record
        db.finish_scan(scan_id, {}, status="INTERRUPTED")
        print("\n⛔ Scan interrupted. Nothing further was sent.", file=sys.stderr)
        return 130
    except Exception:
        db.finish_scan(scan_id, {}, status="FAILED")
        raise
    finally:
        db.close()


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 2