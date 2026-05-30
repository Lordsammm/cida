"""External Attack Surface Mapping ingest.

Supported input formats (auto-detected from JSON / JSONL structure):

1) Shodan host search JSON (`shodan host <ip> --json` or InternetDB API)
   - Array (or {"matches":[...]}) of host records with keys:
     ip_str, port, transport, org, hostnames[], product, vulns{...|[...]},
     ssl{cert{expired,...}}, _shodan.module, location.
   - Emits one Finding per (ip,port). KEV/critical CVEs in `vulns` become
     CRITICAL findings; expired certs become MEDIUM; admin panels HIGH.

2) Censys hosts API JSON (`censys search hosts ...`)
   - Array (or {"result":{"hits":[...]}}) of host docs with keys:
     ip, services[]{port, service_name, transport_protocol, software[]{...}},
     location, autonomous_system.
   - Emits one Finding per service.

3) Amass JSONL (one JSON per line) - subdomain enumeration
   - Records: {"name": "sub.example.com", "addresses":[{"ip":..., "cidr":...}], "sources":[...]}
   - Emits a LOW info-disclosure finding per discovered subdomain, MEDIUM if
     resolves to a public IP (always assumed public for Amass output).

Domain rollup:
- web / http(s) / admin / login → APPSEC
- ssh / rdp / smb / telnet / db ports → NETWORK
- expired cert / weak cert / self-signed → APPSEC
- subdomain discovery → ASSET_DATA (shadow-IT exposure)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from models import Domain, Finding, Severity


_ADMIN_KEYWORDS = ("admin", "phpmyadmin", "cpanel", "webmin", "manager", "console", "dashboard", "kibana", "jenkins")
_DB_PORTS = {1433, 3306, 5432, 6379, 27017, 9200, 5984, 11211, 9042, 1521}
_REMOTE_PORTS = {22, 23, 3389, 5900, 5985, 5986, 445, 139}
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 5000, 3000}


def _sev_for_port(port: int, product: str) -> Severity:
    p = (product or "").lower()
    if port in _DB_PORTS:
        return Severity.HIGH  # publicly-exposed DBs are bad
    if port in (23, 21):  # telnet / ftp
        return Severity.HIGH
    if port in _REMOTE_PORTS:
        return Severity.MEDIUM
    if any(k in p for k in _ADMIN_KEYWORDS):
        return Severity.HIGH
    if port in _WEB_PORTS:
        return Severity.LOW
    return Severity.LOW


def _domain_for_port(port: int, product: str) -> Domain:
    p = (product or "").lower()
    if any(k in p for k in _ADMIN_KEYWORDS) or port in _WEB_PORTS:
        return Domain.APPSEC
    if port in _DB_PORTS:
        return Domain.ASSET_DATA
    if port in _REMOTE_PORTS:
        return Domain.NETWORK
    return Domain.NETWORK


def _parse_shodan(records: Iterable[dict]) -> list[Finding]:
    out: list[Finding] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        ip = rec.get("ip_str") or rec.get("ip") or "unknown-ip"
        port = int(rec.get("port") or 0)
        product = rec.get("product") or rec.get("data") or ""
        hostnames = rec.get("hostnames") or []
        vulns = rec.get("vulns") or {}
        ssl = rec.get("ssl") or {}
        asset = f"shodan:{ip}:{port}" if port else f"shodan:{ip}"

        # 1) Per-host service finding
        sev = _sev_for_port(port, str(product))
        title = f"Exposed service on {port}/{rec.get('transport') or 'tcp'}: {str(product)[:80]}".strip()
        out.append(Finding(
            source="shodan",
            asset=asset,
            title=title[:240],
            severity=sev,
            domain=_domain_for_port(port, str(product)),
            exposure="internet",
            evidence=(", ".join(hostnames[:3]) or None),
            raw={"ip": ip, "port": port, "hostnames": hostnames[:5]},
        ))

        # 2) Per-CVE finding from vulns
        cves: list[str] = []
        if isinstance(vulns, dict):
            cves = list(vulns.keys())
        elif isinstance(vulns, list):
            cves = [str(v) for v in vulns]
        for cve in cves[:50]:
            out.append(Finding(
                source="shodan",
                asset=asset,
                title=f"Public vulnerability {cve} on {ip}:{port}",
                severity=Severity.CRITICAL,
                domain=Domain.NETWORK,
                cve_id=cve,
                exposure="internet",
                evidence=f"Detected by Shodan banner inspection on {ip}:{port}",
                raw={"ip": ip, "port": port},
            ))

        # 3) Expired-cert finding
        cert = (ssl or {}).get("cert") or {}
        if cert.get("expired") is True:
            out.append(Finding(
                source="shodan",
                asset=asset,
                title=f"Expired TLS certificate on {ip}:{port}",
                severity=Severity.MEDIUM,
                domain=Domain.APPSEC,
                exposure="internet",
                evidence=str(cert.get("subject") or "")[:200] or None,
                raw={"ip": ip, "port": port},
            ))
    return out


def _parse_censys(records: Iterable[dict]) -> list[Finding]:
    out: list[Finding] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        ip = rec.get("ip") or "unknown-ip"
        for svc in rec.get("services") or []:
            port = int(svc.get("port") or 0)
            svc_name = svc.get("service_name") or svc.get("extended_service_name") or ""
            software_list = svc.get("software") or []
            product = software_list[0].get("product") if software_list and isinstance(software_list[0], dict) else ""
            asset = f"censys:{ip}:{port}"
            sev = _sev_for_port(port, f"{svc_name} {product}")
            title = f"Exposed {svc_name or 'service'} on {port} ({product})".strip()
            out.append(Finding(
                source="censys",
                asset=asset,
                title=title[:240],
                severity=sev,
                domain=_domain_for_port(port, f"{svc_name} {product}"),
                exposure="internet",
                evidence=(svc.get("banner") or "")[:300] or None,
                raw={"ip": ip, "port": port, "service": svc_name},
            ))
    return out


def _parse_amass(records: Iterable[dict]) -> list[Finding]:
    out: list[Finding] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = rec.get("name") or rec.get("hostname") or ""
        if not name:
            continue
        addrs = rec.get("addresses") or []
        ip = addrs[0].get("ip") if addrs and isinstance(addrs[0], dict) else None
        title = f"Subdomain discovered: {name}"
        out.append(Finding(
            source="amass",
            asset=f"amass:{name}",
            title=title[:240],
            severity=Severity.LOW,
            domain=Domain.ASSET_DATA,
            exposure="internet",
            evidence=(f"Resolves to {ip}" if ip else None),
            raw={"name": name, "ip": ip, "sources": rec.get("sources") or []},
        ))
    return out


def _looks_like_shodan(rec: dict) -> bool:
    return ("ip_str" in rec) or ("_shodan" in rec)


def _looks_like_censys(rec: dict) -> bool:
    return ("services" in rec and isinstance(rec.get("services"), list)) or ("ip" in rec and "autonomous_system" in rec)


def _looks_like_amass(rec: dict) -> bool:
    return "name" in rec and "addresses" in rec


def parse_attack_surface(path: str | Path) -> list[Finding]:
    """Parse Shodan / Censys / Amass output → list[Finding]."""
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []

    # Try JSONL first (Amass output is one JSON per line)
    records: list[dict] = []
    if "\n" in text and text.lstrip().startswith("{"):
        ok_jsonl = True
        tmp: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                tmp.append(json.loads(line))
            except json.JSONDecodeError:
                ok_jsonl = False
                break
        if ok_jsonl and len(tmp) > 1:
            records = tmp

    if not records:
        data = json.loads(text)
        if isinstance(data, dict):
            # Common wrappers
            for key in ("matches", "hits", "results", "data"):
                if key in data and isinstance(data[key], list):
                    records = data[key]
                    break
            # Censys API v2 shape: result.hits
            if not records and "result" in data and isinstance(data["result"], dict):
                hits = data["result"].get("hits")
                if isinstance(hits, list):
                    records = hits
            if not records:
                records = [data]
        elif isinstance(data, list):
            records = data

    if not records:
        return []

    # Dispatch by content shape (first record decides)
    sample = next((r for r in records if isinstance(r, dict)), {})
    if _looks_like_shodan(sample):
        return _parse_shodan(records)
    if _looks_like_amass(sample):
        return _parse_amass(records)
    if _looks_like_censys(sample):
        return _parse_censys(records)

    # Fallback: try all parsers and use whichever produced results
    for fn in (_parse_shodan, _parse_censys, _parse_amass):
        out = fn(records)
        if out:
            return out
    return []
