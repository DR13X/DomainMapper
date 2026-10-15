"""One-command CLI: python -m domainmapper example.test"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from domainmapper.core import save_report, scan


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="domainmapper",
        description="DomainMapper — authorized domain infrastructure reconnaissance (passive).",
    )
    p.add_argument("domain", help="Authorized target domain (e.g. example.test)")
    p.add_argument("-w", "--wordlist", type=Path, help="Optional subdomain wordlist")
    p.add_argument("-o", "--output", default="reports", help="Output directory")
    p.add_argument("-j", "--json", action="store_true", help="Print full JSON to stdout")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--workers", type=int, default=5)
    p.add_argument("--rate", type=float, default=5.0, help="Requests per second")
    p.add_argument("--timeout", type=float, default=8.0)
    args = p.parse_args(argv)

    level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose else logging.INFO)
    logging.basicConfig(level=level, format="%(levelname)s  %(message)s")

    words = None
    if args.wordlist and args.wordlist.exists():
        words = [
            ln.strip()
            for ln in args.wordlist.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]

    try:
        result = scan(
            args.domain,
            wordlist=words,
            workers=args.workers,
            rate=args.rate,
            timeout=args.timeout,
            passive=True,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130

    path = save_report(result, args.output)
    stats = result["stats"]
    print(f"\nDomainMapper — {args.domain}")
    print(f"  Subdomains : {stats['subdomains']}")
    print(f"  IPs        : {stats['ips']}")
    print(f"  Providers  : {stats['providers']}")
    print(f"  Findings   : {stats['findings']}")
    print(f"  Report     : {path}")

    if result["findings"]:
        print("\nFindings:")
        for f in result["findings"]:
            print(f"  [{f['severity'].upper()}] {f['title']} ({f['asset']})")

    if args.json:
        print(json.dumps(result, indent=2, default=str))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
