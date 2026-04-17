"""
NetProbe - Domain Intelligence Toolkit
A comprehensive domain lookup and security analysis tool.
"""

import ipaddress
import logging
import re
import socket
import ssl
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
from flask import Flask, render_template, request, jsonify, abort

import db
import recommendations

app = Flask(__name__)
db.init_db()

log = logging.getLogger("netprobe")

# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_valid_domain(domain):
    """Validate that input looks like a public domain name."""
    if not domain or len(domain) > 253:
        return False
    return _DOMAIN_RE.match(domain) is not None


def _is_private_ip(ip_str):
    """Return True if the IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _is_valid_ip(ip_str):
    """Validate that input is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _safe_resolve_ip(domain):
    """Resolve domain to IP and reject private addresses."""
    ip = socket.gethostbyname(domain)
    if _is_private_ip(ip):
        raise ValueError("Target resolves to a private IP address")
    return ip


def _safe_error(exc):
    """Return a sanitised error message without leaking internals."""
    text = str(exc)
    for word in ("Traceback", "/home/", "/usr/", "File \""):
        if word in text:
            return "An internal error occurred"
    if len(text) > 300:
        text = text[:300]
    return text


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
        return {"success": False, "error": _safe_error(exc)}


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
        dns.name.from_text(domain)
        try:
            dns.resolver.resolve(domain, "DNSKEY")
            has_dnskey = True
        except Exception:
            has_dnskey = False

        try:
            dns.resolver.resolve(domain, "DS")
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
        return {"signed": False, "status": _safe_error(exc)}


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
        for _, value in cert.get("subjectAltName", ()):
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
        return {"success": False, "error": _safe_error(exc)}


# ---------------------------------------------------------------------------
# TLS Deep Scan (Qualys SSL Labs style)
# ---------------------------------------------------------------------------

# Map legacy protocol names to modern ssl.TLSVersion values.
# Entries are skipped silently if the version is disabled in the local OpenSSL build.
_TLS_VERSION_MAP = [
    ("TLS 1.0", "TLSv1"),
    ("TLS 1.1", "TLSv1_1"),
    ("TLS 1.2", "TLSv1_2"),
]
TLS_PROTOCOLS = [
    (name, getattr(ssl.TLSVersion, attr))
    for name, attr in _TLS_VERSION_MAP
    if hasattr(ssl.TLSVersion, attr)
]

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}


def _classify_cipher(cipher_name):
    upper = cipher_name.upper()
    for w in WEAK_CIPHERS:
        if w.upper() in upper:
            return "insecure" if w in ("NULL", "EXPORT", "anon") else "weak"
    if "AES" in upper and ("GCM" in upper or "CHACHA" in upper):
        return "strong"
    if "AES" in upper:
        return "acceptable"
    return "acceptable"


def _has_forward_secrecy(cipher_name):
    upper = cipher_name.upper()
    return "ECDHE" in upper or "DHE" in upper


def _test_protocol(domain, tls_version, port=443, timeout=5):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, port))
            cipher = s.cipher()
            return {
                "supported": True,
                "cipher": cipher[0] if cipher else None,
                "bits": cipher[2] if cipher else None,
                "protocol_version": cipher[1] if cipher else None,
            }
    except Exception:
        return {"supported": False}


def _test_tls13(domain, port=443, timeout=5):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, port))
            cipher = s.cipher()
            return {
                "supported": True,
                "cipher": cipher[0] if cipher else None,
                "bits": cipher[2] if cipher else None,
                "protocol_version": cipher[1] if cipher else None,
            }
    except Exception:
        return {"supported": False}


def _enumerate_ciphers(domain, port=443, timeout=5):
    accepted = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    all_ciphers = ctx.get_ciphers()

    def _try_cipher(c):
        name = c["name"]
        try:
            tctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tctx.check_hostname = False
            tctx.verify_mode = ssl.CERT_NONE
            tctx.set_ciphers(name)
            with tctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(timeout)
                s.connect((domain, port))
                negotiated = s.cipher()
                return {
                    "name": negotiated[0],
                    "protocol": negotiated[1],
                    "bits": negotiated[2],
                    "strength": _classify_cipher(negotiated[0]),
                    "forward_secrecy": _has_forward_secrecy(negotiated[0]),
                }
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_try_cipher, c): c for c in all_ciphers}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result and not any(a["name"] == result["name"] for a in accepted):
                accepted.append(result)

    accepted.sort(key=lambda x: (-x["bits"], x["name"]))
    return accepted


def _check_ocsp_stapling(domain, port=443):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ctx, "set_ocsp_client_callback"):
            ocsp_response = [None]

            def _ocsp_cb(conn, ocsp_data, user_data):
                ocsp_response[0] = ocsp_data
                return True

            ctx.set_ocsp_client_callback(_ocsp_cb)
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, port))
            return ocsp_response[0] is not None and len(ocsp_response[0]) > 0
    except Exception:
        pass
    return False


def _check_tls_compression(domain, port=443):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            return s.compression() is not None
    except Exception:
        return False


def _get_cert_details(domain, port=443):
    result = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, port))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        san = [v for _, v in cert.get("subjectAltName", ())]

        result = {
            "success": True,
            "subject": subject,
            "issuer": issuer,
            "common_name": subject.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", issuer.get("commonName", "")),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "expired": days_left < 0,
            "serial_number": cert.get("serialNumber", ""),
            "version": cert.get("version", ""),
            "san": san,
            "san_count": len(san),
            "wildcard": any(s.startswith("*.") for s in san),
            "self_signed": subject == issuer,
        }
    except ssl.SSLCertVerificationError as exc:
        result = {"success": False, "trusted": False, "error": _safe_error(exc)}
    except Exception as exc:
        result = {"success": False, "error": _safe_error(exc)}
    return result


def _calculate_tls_grade(protocols, ciphers, cert, has_ocsp, has_compression, has_hsts):
    score = 100
    warnings = []

    if not cert.get("success"):
        return "T", ["Certificate not trusted"]
    if cert.get("expired"):
        return "T", ["Certificate expired"]
    if cert.get("self_signed"):
        score -= 40
        warnings.append("Self-signed certificate")

    proto_map = {p["name"]: p["supported"] for p in protocols}
    if proto_map.get("TLS 1.0"):
        score -= 15
        warnings.append("TLS 1.0 supported (deprecated)")
    if proto_map.get("TLS 1.1"):
        score -= 10
        warnings.append("TLS 1.1 supported (deprecated)")
    if not proto_map.get("TLS 1.2") and not proto_map.get("TLS 1.3"):
        score -= 30
        warnings.append("Neither TLS 1.2 nor 1.3 supported")
    if not proto_map.get("TLS 1.3"):
        score -= 5
        warnings.append("TLS 1.3 not supported")

    has_weak = any(c["strength"] in ("weak", "insecure") for c in ciphers)
    has_fs = any(c["forward_secrecy"] for c in ciphers)
    all_fs = all(c["forward_secrecy"] for c in ciphers) if ciphers else False

    if has_weak:
        score -= 20
        warnings.append("Weak cipher suites accepted")
    if not has_fs:
        score -= 15
        warnings.append("No forward secrecy")

    if has_compression:
        score -= 15
        warnings.append("TLS compression enabled (CRIME vulnerable)")

    if not has_ocsp:
        score -= 5
        warnings.append("No OCSP stapling")

    if not has_hsts:
        score -= 5
        warnings.append("HSTS not set")

    if score >= 95 and has_hsts and all_fs and not has_weak:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    return grade, warnings


def check_tls_deep(domain, port=443):
    results = {"success": False}

    try:
        protocols = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for name, const in TLS_PROTOCOLS:
                futures[executor.submit(_test_protocol, domain, const, port)] = name
            futures[executor.submit(_test_tls13, domain, port)] = "TLS 1.3"

            for future in concurrent.futures.as_completed(futures):
                pname = futures[future]
                res = future.result()
                res["name"] = pname
                protocols.append(res)

        protocols.sort(key=lambda x: x["name"])
        ciphers = _enumerate_ciphers(domain, port)
        cert = _get_cert_details(domain, port)
        has_ocsp = _check_ocsp_stapling(domain, port)
        has_compression = _check_tls_compression(domain, port)

        has_hsts = False
        hsts_value = ""
        hsts_preload = False
        try:
            resp = requests.get(
                f"https://{domain}", timeout=10, allow_redirects=True,
            )
            hsts_value = resp.headers.get("Strict-Transport-Security", "")
            has_hsts = len(hsts_value) > 0
            hsts_preload = "preload" in hsts_value.lower()
        except Exception:
            pass

        grade, warnings = _calculate_tls_grade(
            protocols, ciphers, cert, has_ocsp, has_compression, has_hsts
        )

        strong_count = sum(1 for c in ciphers if c["strength"] == "strong")
        acceptable_count = sum(1 for c in ciphers if c["strength"] == "acceptable")
        weak_count = sum(1 for c in ciphers if c["strength"] == "weak")
        insecure_count = sum(1 for c in ciphers if c["strength"] == "insecure")
        fs_count = sum(1 for c in ciphers if c["forward_secrecy"])

        results = {
            "success": True,
            "grade": grade,
            "warnings": warnings,
            "protocols": protocols,
            "ciphers": ciphers,
            "cipher_summary": {
                "total": len(ciphers),
                "strong": strong_count,
                "acceptable": acceptable_count,
                "weak": weak_count,
                "insecure": insecure_count,
                "forward_secrecy": fs_count,
            },
            "certificate": cert,
            "ocsp_stapling": has_ocsp,
            "tls_compression": has_compression,
            "hsts": {
                "enabled": has_hsts,
                "value": hsts_value,
                "preload": hsts_preload,
            },
        }

    except Exception as exc:
        results = {"success": False, "error": _safe_error(exc)}

    return results


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
        results["error"] = _safe_error(exc)
    return results


# ---------------------------------------------------------------------------
# HTTPS redirect check
# ---------------------------------------------------------------------------

def check_https_redirect(domain):
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
        return {"redirects": False, "pass": False, "error": _safe_error(exc)}


# ---------------------------------------------------------------------------
# IPv6 support
# ---------------------------------------------------------------------------

def check_ipv6(domain):
    aaaa = _resolve(domain, "AAAA")
    mx_records = _resolve(domain, "MX")
    mx_ipv6 = {}
    for mx in mx_records:
        mx_host = mx.split()[-1].rstrip(".")
        mx_aaaa = _resolve(mx_host, "AAAA")
        if mx_aaaa:
            mx_ipv6[mx_host] = mx_aaaa

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

def _dnsbl_is_real_hit(answers):
    """Return True only for genuine listing responses (127.0.0.x, x<128).

    Spamhaus and some others return 127.255.255.252–255 to signal quota/auth
    errors, not actual listings.  Treating those as hits causes false positives.
    """
    for rdata in answers:
        txt = rdata.to_text()
        parts = txt.split(".")
        if len(parts) == 4 and parts[0] == "127":
            # 127.255.x.x → error/quota response, not a real listing
            if parts[1] == "255":
                return False
            return True
    return False


def check_blacklist(domain):
    results = {"listed": [], "clean": [], "errors": [], "ip": None}
    try:
        ip = _safe_resolve_ip(domain)
        results["ip"] = ip
        reversed_ip = ".".join(reversed(ip.split(".")))

        for bl in DNSBL_SERVERS:
            query = f"{reversed_ip}.{bl}"
            try:
                answers = dns.resolver.resolve(query, "A")
                if _dnsbl_is_real_hit(answers):
                    results["listed"].append(bl)
                else:
                    results["errors"].append(bl)
                    results["clean"].append(bl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                results["clean"].append(bl)
            except Exception:
                results["clean"].append(bl)

        results["is_listed"] = len(results["listed"]) > 0
    except Exception as exc:
        results["error"] = _safe_error(exc)
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def check_ports(domain):
    results = {"open": [], "closed": [], "ip": None}
    try:
        ip = _safe_resolve_ip(domain)
        results["ip"] = ip

        with concurrent.futures.ThreadPoolExecutor(max_workers=17) as executor:
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
        results["error"] = _safe_error(exc)
    return results


# ---------------------------------------------------------------------------
# Full Scan (all checks combined)
# ---------------------------------------------------------------------------

def full_scan(domain):
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
            executor.submit(check_tls_deep, domain): "tls_deep",
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
                results[key] = {"error": _safe_error(exc)}

    return results


# ---------------------------------------------------------------------------
# Security headers for our own responses
# ---------------------------------------------------------------------------

@app.after_request
def _set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory)
# ---------------------------------------------------------------------------

_rate_store = {}
_RATE_LIMIT = 10
_RATE_WINDOW = 60


def _check_rate_limit(ip):
    now = datetime.now(timezone.utc).timestamp()
    if ip not in _rate_store:
        _rate_store[ip] = []
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    domain = data.get("domain", "")
    if not isinstance(domain, str):
        return jsonify({"error": "Invalid domain"}), 400

    domain = domain.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")

    if not _is_valid_domain(domain):
        return jsonify({"error": "Invalid domain name. Use format: example.com"}), 400

    checks = data.get("checks", ["all"])
    if not isinstance(checks, list):
        return jsonify({"error": "Invalid checks parameter"}), 400
    checks = [c for c in checks if isinstance(c, str)]

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
            "tls_deep": lambda: check_tls_deep(domain),
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
                    results[key] = {"error": _safe_error(exc)}

    results["domain"] = domain
    results["timestamp"] = datetime.now(timezone.utc).isoformat()

    save = data.get("save_history", True)
    if save:
        try:
            scan_id = db.save_scan(domain, results)
            results["scan_id"] = scan_id
        except Exception as exc:
            log.warning("Failed to store scan history: %s", exc)

    return jsonify(results)


@app.route("/api/history", methods=["GET"])
def api_history_list():
    domain_filter = request.args.get("domain", "").strip().lower() or None
    if domain_filter and not _is_valid_domain(domain_filter):
        return jsonify({"error": "Invalid domain filter"}), 400
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    limit = max(1, min(limit, 500))

    scans = db.list_scans(domain=domain_filter, limit=limit)
    stats = db.history_stats()
    return jsonify({"scans": scans, "stats": stats})


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def api_history_get(scan_id):
    record = db.get_scan(scan_id)
    if not record:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(record)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def api_history_delete(scan_id):
    if not db.delete_scan(scan_id):
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"deleted": True})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    db.clear_history()
    return jsonify({"cleared": True})


@app.route("/api/recommendations/<int:scan_id>", methods=["GET"])
def api_recommendations(scan_id):
    record = db.get_scan(scan_id)
    if not record:
        return jsonify({"error": "Scan not found"}), 404
    recs = recommendations.generate(record["data"])
    counts = recommendations.summarize_counts(recs)
    return jsonify({
        "scan_id": scan_id,
        "domain": record["domain"],
        "created_at": record["created_at"],
        "recommendations": recs,
        "counts": counts,
    })


@app.route("/report/<int:scan_id>")
def report_view(scan_id):
    record = db.get_scan(scan_id)
    if not record:
        abort(404)
    recs = recommendations.generate(record["data"])
    counts = recommendations.summarize_counts(recs)
    return render_template(
        "report.html",
        scan=record,
        results=record["data"],
        recommendations=recs,
        counts=counts,
    )


@app.route("/api/reverse-dns", methods=["POST"])
def api_reverse_dns():
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    ip = data.get("ip", "")
    if not isinstance(ip, str):
        return jsonify({"error": "Invalid IP"}), 400
    ip = ip.strip()

    if not _is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address format"}), 400

    results = lookup_reverse_dns(ip)
    return jsonify({"ip": ip, "ptr_records": results})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
