"""
NetProbe - Domain Intelligence Toolkit
A comprehensive domain lookup and security analysis tool.
"""

import json
import socket
import ssl
import struct
import time
import concurrent.futures
from datetime import datetime, timezone

import dns.resolver
import dns.reversename
import dns.dnssec
import dns.name
import dns.rdatatype
import dns.query
import dns.zone
import requests
import whois
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(value):
    """Convert non-serializable types to strings."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _resolve(domain, rdtype):
    """Resolve DNS records, return list of strings."""
    try:
        answers = dns.resolver.resolve(domain, rdtype)
        return [r.to_text() for r in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def lookup_whois(domain):
    """Return parsed WHOIS data."""
    try:
        w = whois.whois(domain)
        data = {}
        for key in (
            "domain_name", "registrar", "whois_server", "creation_date",
            "expiration_date", "updated_date", "name_servers", "status",
            "emails", "dnssec", "org", "address", "city", "state",
            "country", "registrant_postal_code",
        ):
            val = getattr(w, key, None)
            if val is not None:
                data[key] = _clean(val)
        return {"success": True, "data": data}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# DNS Records
# ---------------------------------------------------------------------------

DNS_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR",
]

def lookup_dns(domain):
    """Return all common DNS records."""
    results = {}
    for rtype in DNS_RECORD_TYPES:
        records = _resolve(domain, rtype)
        if records:
            results[rtype] = records
    return results


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def lookup_reverse_dns(ip):
    """Return reverse DNS for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return [r.to_text() for r in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# DNSSEC validation
# ---------------------------------------------------------------------------

def check_dnssec(domain):
    """Check if DNSSEC is enabled for the domain."""
    try:
        name = dns.name.from_text(domain)
        # Look for DNSKEY
        try:
            dnskeys = dns.resolver.resolve(domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            has_dnskey = False

        # Look for DS in parent
        try:
            ds_records = dns.resolver.resolve(domain, "DS")
            has_ds = True
        except Exception:
            has_ds = False

        signed = has_dnskey and has_ds
        return {
            "signed": signed,
            "has_dnskey": has_dnskey,
            "has_ds": has_ds,
            "status": "DNSSEC enabled" if signed else "DNSSEC not fully configured",
        }
    except Exception as exc:
        return {"signed": False, "status": str(exc)}


# ---------------------------------------------------------------------------
# E-mail security: SPF, DMARC, DKIM, MTA-STS, TLSRPT
# ---------------------------------------------------------------------------

def check_spf(domain):
    """Check SPF record."""
    txts = _resolve(domain, "TXT")
    for txt in txts:
        clean = txt.strip('"')
        if clean.lower().startswith("v=spf1"):
            mechanisms = clean.split()
            has_all = any(m in ("-all", "~all", "?all") for m in mechanisms)
            strict = "-all" in mechanisms
            return {
                "found": True,
                "record": clean,
                "has_all_mechanism": has_all,
                "strict": strict,
                "pass": has_all,
            }
    return {"found": False, "pass": False}


def check_dmarc(domain):
    """Check DMARC record."""
    records = _resolve(f"_dmarc.{domain}", "TXT")
    for r in records:
        clean = r.strip('"')
        if clean.lower().startswith("v=dmarc1"):
            policy = "none"
            for part in clean.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy = part.split("=", 1)[1].strip().lower()
            return {
                "found": True,
                "record": clean,
                "policy": policy,
                "pass": policy in ("reject", "quarantine"),
            }
    return {"found": False, "pass": False}


def check_dkim(domain, selectors=None):
    """Check common DKIM selectors."""
    if selectors is None:
        selectors = [
            "default", "google", "selector1", "selector2", "k1", "k2",
            "mail", "dkim", "s1", "s2", "sig1", "sm1", "sm2",
            "mandrill", "everlytickey1", "everlytickey2", "mxvault",
        ]
    found = []
    for sel in selectors:
        records = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        if records:
            found.append({"selector": sel, "record": records[0].strip('"')})
    return {"found": len(found) > 0, "selectors": found, "pass": len(found) > 0}


def check_mta_sts(domain):
    """Check MTA-STS DNS record."""
    records = _resolve(f"_mta-sts.{domain}", "TXT")
    for r in records:
        clean = r.strip('"')
        if "v=sts" in clean.lower() or "v=STSv1" in clean:
            return {"found": True, "record": clean, "pass": True}
    return {"found": False, "pass": False}


def check_tlsrpt(domain):
    """Check TLS-RPT DNS record."""
    records = _resolve(f"_smtp._tls.{domain}", "TXT")
    for r in records:
        clean = r.strip('"')
        if "v=tlsrpt" in clean.lower() or "v=TLSRPTv1" in clean:
            return {"found": True, "record": clean, "pass": True}
    return {"found": False, "pass": False}


# ---------------------------------------------------------------------------
# SSL / TLS certificate
# ---------------------------------------------------------------------------

def check_ssl(domain, port=443):
    """Retrieve and analyse the SSL/TLS certificate."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()
            cipher = s.cipher()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        san = []
        for entry_type, value in cert.get("subjectAltName", ()):
            san.append(value)

        return {
            "success": True,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "expired": days_left < 0,
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "san": san,
            "cipher": cipher[0] if cipher else None,
            "protocol": cipher[1] if cipher else None,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# HTTP Security Headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

def check_http_headers(domain):
    """Check HTTP security headers."""
    results = {"headers_found": {}, "headers_missing": [], "score": 0}
    try:
        resp = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
        total = len(SECURITY_HEADERS)
        found = 0
        for hdr in SECURITY_HEADERS:
            val = resp.headers.get(hdr)
            if val:
                results["headers_found"][hdr] = val
                found += 1
            else:
                results["headers_missing"].append(hdr)
        results["score"] = round((found / total) * 100)
        results["status_code"] = resp.status_code
        results["final_url"] = resp.url
        results["server"] = resp.headers.get("Server", "")
        results["success"] = True
    except Exception as exc:
        results["success"] = False
        results["error"] = str(exc)
    return results


# ---------------------------------------------------------------------------
# HTTPS redirect check
# ---------------------------------------------------------------------------

def check_https_redirect(domain):
    """Check if HTTP redirects to HTTPS."""
    try:
        resp = requests.get(f"http://{domain}", timeout=10, allow_redirects=False)
        redirects_to_https = (
            resp.status_code in (301, 302, 307, 308)
            and resp.headers.get("Location", "").startswith("https://")
        )
        return {
            "redirects": redirects_to_https,
            "status_code": resp.status_code,
            "location": resp.headers.get("Location", ""),
            "permanent": resp.status_code in (301, 308),
            "pass": redirects_to_https,
        }
    except Exception as exc:
        return {"redirects": False, "pass": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# IPv6 support
# ---------------------------------------------------------------------------

def check_ipv6(domain):
    """Check if the domain has AAAA records (IPv6)."""
    aaaa = _resolve(domain, "AAAA")
    # Also check if the mail servers have IPv6
    mx_records = _resolve(domain, "MX")
    mx_ipv6 = {}
    for mx in mx_records:
        mx_host = mx.split()[-1].rstrip(".")
        mx_aaaa = _resolve(mx_host, "AAAA")
        if mx_aaaa:
            mx_ipv6[mx_host] = mx_aaaa

    # Check nameserver IPv6
    ns_records = _resolve(domain, "NS")
    ns_ipv6 = {}
    for ns in ns_records:
        ns_host = ns.rstrip(".")
        ns_aaaa = _resolve(ns_host, "AAAA")
        if ns_aaaa:
            ns_ipv6[ns_host] = ns_aaaa

    return {
        "has_ipv6": len(aaaa) > 0,
        "aaaa_records": aaaa,
        "mx_ipv6": mx_ipv6,
        "ns_ipv6": ns_ipv6,
        "web_pass": len(aaaa) > 0,
        "mail_pass": len(mx_ipv6) > 0,
        "ns_pass": len(ns_ipv6) > 0,
    }


# ---------------------------------------------------------------------------
# DNSBL / Blacklist Check
# ---------------------------------------------------------------------------

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
]

def check_blacklist(domain):
    """Check if the domain's IP is on common DNS blacklists."""
    results = {"listed": [], "clean": [], "ip": None}
    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip
        reversed_ip = ".".join(reversed(ip.split(".")))

        for bl in DNSBL_SERVERS:
            query = f"{reversed_ip}.{bl}"
            try:
                dns.resolver.resolve(query, "A")
                results["listed"].append(bl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                results["clean"].append(bl)
            except Exception:
                results["clean"].append(bl)

        results["is_listed"] = len(results["listed"]) > 0
    except Exception as exc:
        results["error"] = str(exc)
        results["is_listed"] = False
    return results


# ---------------------------------------------------------------------------
# Open Port Scanner (common ports)
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def _check_port(ip, port, timeout=3):
    """Check if a single port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def check_ports(domain):
    """Scan common ports on the domain."""
    results = {"open": [], "closed": [], "ip": None}
    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(_check_port, ip, port): port
                for port in COMMON_PORTS
            }
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                if future.result():
                    results["open"].append({"port": port, "service": COMMON_PORTS[port]})
                else:
                    results["closed"].append({"port": port, "service": COMMON_PORTS[port]})

        results["open"].sort(key=lambda x: x["port"])
        results["closed"].sort(key=lambda x: x["port"])
    except Exception as exc:
        results["error"] = str(exc)
    return results


# ---------------------------------------------------------------------------
# Full Scan (all checks combined)
# ---------------------------------------------------------------------------

def full_scan(domain):
    """Run all checks and return combined results."""
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = {
            executor.submit(lookup_whois, domain): "whois",
            executor.submit(lookup_dns, domain): "dns",
            executor.submit(check_dnssec, domain): "dnssec",
            executor.submit(check_spf, domain): "spf",
            executor.submit(check_dmarc, domain): "dmarc",
            executor.submit(check_dkim, domain): "dkim",
            executor.submit(check_mta_sts, domain): "mta_sts",
            executor.submit(check_tlsrpt, domain): "tlsrpt",
            executor.submit(check_ssl, domain): "ssl",
            executor.submit(check_http_headers, domain): "http_headers",
            executor.submit(check_https_redirect, domain): "https_redirect",
            executor.submit(check_ipv6, domain): "ipv6",
            executor.submit(check_blacklist, domain): "blacklist",
            executor.submit(check_ports, domain): "ports",
        }
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                results[key] = {"error": str(exc)}

    return results


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower()

    # Strip protocol if provided
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")

    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    checks = data.get("checks", ["all"])

    if "all" in checks:
        results = full_scan(domain)
    else:
        results = {}
        check_map = {
            "whois": lambda: lookup_whois(domain),
            "dns": lambda: lookup_dns(domain),
            "dnssec": lambda: check_dnssec(domain),
            "spf": lambda: check_spf(domain),
            "dmarc": lambda: check_dmarc(domain),
            "dkim": lambda: check_dkim(domain),
            "mta_sts": lambda: check_mta_sts(domain),
            "tlsrpt": lambda: check_tlsrpt(domain),
            "ssl": lambda: check_ssl(domain),
            "http_headers": lambda: check_http_headers(domain),
            "https_redirect": lambda: check_https_redirect(domain),
            "ipv6": lambda: check_ipv6(domain),
            "blacklist": lambda: check_blacklist(domain),
            "ports": lambda: check_ports(domain),
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            futures = {}
            for c in checks:
                if c in check_map:
                    futures[executor.submit(check_map[c])] = c
            for future in concurrent.futures.as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    results[key] = {"error": str(exc)}

    results["domain"] = domain
    results["timestamp"] = datetime.now(timezone.utc).isoformat()
    return jsonify(results)


@app.route("/api/reverse-dns", methods=["POST"])
def api_reverse_dns():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    results = lookup_reverse_dns(ip)
    return jsonify({"ip": ip, "ptr_records": results})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
