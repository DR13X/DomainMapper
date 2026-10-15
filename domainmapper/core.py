"""DomainMapper core — passive domain reconnaissance for authorized targets only."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import dns.resolver

LOG = logging.getLogger("domainmapper")

# ── Scope ──────────────────────────────────────────────────────────


@dataclass
class Scope:
    domains: list[str]
    sub_patterns: list[str] = field(default_factory=list)

    def allows(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        for d in self.domains:
            if name == d or name.endswith("." + d):
                return True
        for p in self.sub_patterns:
            if p.startswith("*.") and (name == p[2:] or name.endswith("." + p[2:])):
                return True
        return False


# ── Rate limit ─────────────────────────────────────────────────────


class RateLimit:
    def __init__(self, rps: float = 5.0) -> None:
        self.interval = 1.0 / max(rps, 0.1)
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        gap = self.interval - (now - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.monotonic()


# ── DNS ────────────────────────────────────────────────────────────


def _resolve(name: str, rdtype: str, timeout: float = 5.0) -> list[str]:
    try:
        r = dns.resolver.Resolver()
        r.lifetime = timeout
        answers = r.resolve(name, rdtype, raise_on_no_answer=False)
        if not answers or answers.rrset is None:
            return []
        out: list[str] = []
        for a in answers:
            if rdtype in ("A", "AAAA"):
                out.append(str(a.address))
            elif rdtype == "MX":
                out.append(str(a.exchange).rstrip("."))
            elif rdtype in ("NS", "CNAME", "PTR"):
                out.append(str(getattr(a, "target", a)).rstrip("."))
            elif rdtype == "TXT":
                parts = [
                    p.decode() if isinstance(p, bytes) else str(p) for p in a.strings
                ]
                out.append("".join(parts))
            elif rdtype == "SOA":
                out.append(f"{a.mname} serial={a.serial}")
            elif rdtype == "CAA":
                out.append(f"{a.flags} {a.tag} {a.value}")
            else:
                out.append(str(a))
        return out
    except Exception:
        return []


# ── CT subdomains (passive) ────────────────────────────────────────


def ct_subdomains(domain: str, timeout: float = 15.0) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found: set[str] = set()
    try:
        req = Request(url, headers={"User-Agent": "DomainMapper/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        for entry in data if isinstance(data, list) else []:
            raw = entry.get("name_value") or entry.get("common_name") or ""
            for line in raw.replace(",", "\n").splitlines():
                n = line.strip().lower().lstrip("*.")
                if n and (n == domain or n.endswith("." + domain)):
                    if re.match(r"^[a-z0-9.-]+$", n):
                        found.add(n)
    except Exception as exc:
        LOG.debug("CT lookup failed: %s", exc)
    return sorted(found)


# ── IP enrichment (best-effort, no key) ────────────────────────────


def enrich_ip(ip: str, timeout: float = 5.0) -> dict[str, Any]:
    info: dict[str, Any] = {"ip": ip, "version": 4 if "." in ip else 6}
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            info["private"] = True
            return info
    except ValueError:
        return info
    # reverse DNS
    try:
        info["ptr"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        info["ptr"] = None
    # free IP API
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,asname"
        with urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            info.update(
                {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "asn_name": data.get("asname"),
                }
            )
    except Exception:
        pass
    return info


# ── Cloud hints ────────────────────────────────────────────────────

CLOUD_ASN = {
    13335: "Cloudflare",
    16509: "Amazon Web Services",
    14618: "Amazon Web Services",
    8075: "Microsoft Azure",
    15169: "Google Cloud",
    14061: "DigitalOcean",
    20940: "Akamai",
    54113: "Fastly",
}
CLOUD_CNAME = [
    (r"\.cloudflare\.(com|net)$", "Cloudflare"),
    (r"\.cloudfront\.net$", "Amazon CloudFront"),
    (r"\.amazonaws\.com$", "Amazon Web Services"),
    (r"\.azurewebsites\.net$", "Microsoft Azure"),
    (r"\.googleusercontent\.com$", "Google Cloud"),
    (r"\.github\.io$", "GitHub Pages"),
    (r"\.netlify\.app$", "Netlify"),
    (r"\.vercel\.app$", "Vercel"),
]


def detect_cloud(ips: list[dict], cnames: list[str]) -> list[dict]:
    hits: dict[str, dict] = {}
    for ip in ips:
        asn_str = str(ip.get("asn") or "")
        m = re.search(r"AS(\d+)", asn_str)
        if m:
            num = int(m.group(1))
            if num in CLOUD_ASN:
                name = CLOUD_ASN[num]
                hits[name] = {
                    "provider": name,
                    "confidence": 85,
                    "evidence": [f"ASN {asn_str}"],
                }
    for cn in cnames:
        for pat, name in CLOUD_CNAME:
            if re.search(pat, cn, re.I):
                if name not in hits:
                    hits[name] = {
                        "provider": name,
                        "confidence": 90,
                        "evidence": [f"CNAME {cn}"],
                    }
                else:
                    hits[name]["evidence"].append(f"CNAME {cn}")
                    hits[name]["confidence"] = min(100, hits[name]["confidence"] + 5)
    return list(hits.values())


# ── Findings ───────────────────────────────────────────────────────


def analyze(domain: str, dns_data: dict, subs: list[dict]) -> list[dict]:
    findings: list[dict] = []
    txts = [t.lower() for t in dns_data.get("TXT", [])]
    if not any(t.startswith("v=spf1") for t in txts):
        findings.append(
            {
                "title": "Missing SPF record",
                "severity": "medium",
                "evidence": "No v=spf1 TXT",
                "asset": domain,
            }
        )
    if not dns_data.get("CAA"):
        findings.append(
            {
                "title": "Missing CAA records",
                "severity": "low",
                "evidence": "No CAA records",
                "asset": domain,
            }
        )
    for s in subs:
        cn = s.get("cname")
        if cn and not s.get("a") and not s.get("aaaa"):
            if re.search(
                r"\.(github\.io|azurewebsites\.net|herokuapp\.com|s3\.amazonaws\.com|netlify\.app|vercel\.app)$",
                cn,
                re.I,
            ):
                findings.append(
                    {
                        "title": "Potential dangling CNAME",
                        "severity": "medium",
                        "evidence": f"{s['name']} → {cn} (no A/AAAA)",
                        "asset": s["name"],
                    }
                )
    return findings


# ── Main scan ──────────────────────────────────────────────────────


def scan(
    domain: str,
    *,
    wordlist: list[str] | None = None,
    workers: int = 5,
    rate: float = 5.0,
    timeout: float = 8.0,
    passive: bool = True,
) -> dict[str, Any]:
    """Run authorized passive reconnaissance against a single domain."""
    domain = domain.lower().rstrip(".")
    scope = Scope(domains=[domain], sub_patterns=[f"*.{domain}"])
    if not scope.allows(domain):
        raise ValueError(f"Out of scope: {domain}")

    rl = RateLimit(rate)
    LOG.info("Scanning %s (passive=%s)", domain, passive)

    # DNS
    dns_data: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"):
        rl.wait()
        dns_data[rtype] = _resolve(domain, rtype, timeout)

    # Subdomains
    names: set[str] = {domain}
    for n in ct_subdomains(domain, timeout=timeout + 5):
        if scope.allows(n):
            names.add(n)
    if wordlist:
        for w in wordlist:
            w = w.strip().lower()
            if w and not w.startswith("#"):
                cand = f"{w}.{domain}"
                if scope.allows(cand):
                    names.add(cand)

    def resolve_host(name: str) -> dict[str, Any]:
        rl.wait()
        a = _resolve(name, "A", timeout)
        aaaa = _resolve(name, "AAAA", timeout)
        cname = _resolve(name, "CNAME", timeout)
        return {
            "name": name,
            "a": a,
            "aaaa": aaaa,
            "cname": cname[0] if cname else None,
            "active": bool(a or aaaa or cname),
        }

    subs: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(resolve_host, n): n for n in sorted(names)}
        for fut in as_completed(futs):
            try:
                subs.append(fut.result())
            except Exception as exc:
                LOG.debug("resolve error: %s", exc)

    # IPs
    ip_set: set[str] = set()
    for s in subs:
        ip_set.update(s.get("a") or [])
        ip_set.update(s.get("aaaa") or [])
    ip_set.update(dns_data.get("A") or [])
    ip_set.update(dns_data.get("AAAA") or [])

    ips: list[dict] = []
    for ip in sorted(ip_set):
        rl.wait()
        ips.append(enrich_ip(ip, timeout))

    cnames = [s["cname"] for s in subs if s.get("cname")]
    providers = detect_cloud(ips, cnames)
    findings = analyze(domain, dns_data, subs)

    result = {
        "meta": {
            "tool": "DomainMapper",
            "version": "1.0.0",
            "domain": domain,
            "passive": passive,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "dns": dns_data,
        "subdomains": subs,
        "ips": ips,
        "providers": providers,
        "findings": findings,
        "stats": {
            "subdomains": len(subs),
            "ips": len(ips),
            "providers": len(providers),
            "findings": len(findings),
        },
    }
    LOG.info(
        "Done: %d subs, %d ips, %d findings",
        len(subs),
        len(ips),
        len(findings),
    )
    return result


def save_report(result: dict, out_dir: str | Path = "reports") -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    domain = result["meta"]["domain"].replace(".", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out / f"{domain}_{ts}.json"
    path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return path
