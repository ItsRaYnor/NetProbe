"""
Remediation suggestions for NetProbe findings.
Generates a list of concrete, actionable fixes based on scan results.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"


def _r(severity, category, title, problem, fix, reference=None):
    rec = {
        "severity": severity,
        "category": category,
        "title": title,
        "problem": problem,
        "fix": fix,
    }
    if reference:
        rec["reference"] = reference
    return rec


def _dnssec(results):
    out = []
    dnssec = results.get("dnssec")
    if not dnssec:
        return out
    if not dnssec.get("signed"):
        out.append(_r(
            SEVERITY_MEDIUM, "DNS", "DNSSEC not configured",
            "DNSSEC is not fully set up. Responses cannot be cryptographically verified, so attackers may inject spoofed DNS records.",
            "Enable DNSSEC at your DNS provider. Publish DNSKEY records and a DS record at the parent zone (registrar). Verify with `dig +dnssec` or dnsviz.net.",
            "https://www.cloudflare.com/dns/dnssec/how-dnssec-works/",
        ))
    return out


def _spf(results):
    out = []
    spf = results.get("spf")
    if not spf:
        return out
    if not spf.get("found"):
        out.append(_r(
            SEVERITY_HIGH, "Email", "SPF record missing",
            "No SPF record was found. Without SPF, anyone can spoof mail from your domain.",
            "Publish a TXT record on the apex: `v=spf1 include:_spf.yourprovider.com -all`. Start with `~all` during roll-out, then move to `-all`.",
            "https://datatracker.ietf.org/doc/html/rfc7208",
        ))
    elif not spf.get("strict"):
        out.append(_r(
            SEVERITY_MEDIUM, "Email", "SPF not strict (~all / ?all)",
            "SPF exists but the final mechanism is not `-all`, so receivers may still accept spoofed mail.",
            "Once you have verified every legitimate sending source, tighten the SPF record to end with `-all`.",
        ))
    return out


def _dmarc(results):
    out = []
    dmarc = results.get("dmarc")
    if not dmarc:
        return out
    if not dmarc.get("found"):
        out.append(_r(
            SEVERITY_HIGH, "Email", "DMARC record missing",
            "No DMARC policy is published. Receivers have no instructions for handling spoofed mail that fails SPF or DKIM.",
            "Publish `_dmarc.yourdomain` TXT: `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain; fo=1`. Monitor aggregate reports for a few weeks, then move to `p=quarantine` and finally `p=reject`.",
            "https://datatracker.ietf.org/doc/html/rfc7489",
        ))
    else:
        policy = (dmarc.get("policy") or "").lower()
        if policy == "none":
            out.append(_r(
                SEVERITY_MEDIUM, "Email", "DMARC policy is p=none",
                "DMARC is published but only in monitor mode. Spoofed mail is not blocked.",
                "After reviewing aggregate (rua) reports, change the policy to `p=quarantine` and eventually `p=reject`.",
            ))
    return out


def _dkim(results):
    out = []
    dkim = results.get("dkim")
    if not dkim:
        return out
    if not dkim.get("found"):
        out.append(_r(
            SEVERITY_MEDIUM, "Email", "No DKIM selectors detected",
            "No DKIM public keys were found for the common selectors tested. Mail from your domain may not be DKIM-signed.",
            "Enable DKIM signing at your mail provider. Publish the generated public key as `<selector>._domainkey.yourdomain` TXT record. Use at least 2048-bit RSA.",
            "https://datatracker.ietf.org/doc/html/rfc6376",
        ))
    return out


def _mta_sts(results):
    out = []
    mta = results.get("mta_sts")
    if mta and not mta.get("found"):
        out.append(_r(
            SEVERITY_LOW, "Email", "MTA-STS not configured",
            "Without MTA-STS, inbound mail can be delivered over unencrypted or misconfigured TLS connections.",
            "Publish `_mta-sts.yourdomain` TXT (`v=STSv1; id=<timestamp>`) and host an HTTPS policy file at `https://mta-sts.yourdomain/.well-known/mta-sts.txt` listing your MX hosts and `mode: enforce`.",
            "https://datatracker.ietf.org/doc/html/rfc8461",
        ))
    return out


def _tlsrpt(results):
    out = []
    rpt = results.get("tlsrpt")
    if rpt and not rpt.get("found"):
        out.append(_r(
            SEVERITY_LOW, "Email", "TLS-RPT not configured",
            "TLS-RPT is not set up. You won't receive reports about TLS failures on inbound mail.",
            "Publish `_smtp._tls.yourdomain` TXT record: `v=TLSRPTv1; rua=mailto:tls-reports@yourdomain`.",
            "https://datatracker.ietf.org/doc/html/rfc8460",
        ))
    return out


def _tls(results):
    out = []
    tls = results.get("tls_deep")
    if not tls or not tls.get("success"):
        return out

    grade = tls.get("grade")
    if grade in ("D", "F", "T"):
        out.append(_r(
            SEVERITY_CRITICAL, "TLS", f"Poor TLS grade ({grade})",
            "The TLS configuration scored a failing grade. Connections are exposed to known attacks.",
            "Address the warnings below: disable obsolete protocols, remove weak ciphers, install a trusted certificate, and enable HSTS.",
            "https://ssl-config.mozilla.org/",
        ))

    protocols = {p.get("name"): p.get("supported") for p in (tls.get("protocols") or [])}
    if protocols.get("TLS 1.0"):
        out.append(_r(
            SEVERITY_HIGH, "TLS", "TLS 1.0 enabled",
            "TLS 1.0 is deprecated (PCI-DSS forbids it) and vulnerable to BEAST and downgrade attacks.",
            "Disable TLS 1.0 in the web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`.",
        ))
    if protocols.get("TLS 1.1"):
        out.append(_r(
            SEVERITY_HIGH, "TLS", "TLS 1.1 enabled",
            "TLS 1.1 is deprecated (RFC 8996). Browsers have removed support.",
            "Disable TLS 1.1 and require TLS 1.2 as a minimum.",
        ))
    if not protocols.get("TLS 1.3"):
        out.append(_r(
            SEVERITY_LOW, "TLS", "TLS 1.3 not available",
            "TLS 1.3 is not offered. You miss performance and security improvements (0-RTT, cleaner handshake).",
            "Upgrade OpenSSL (>=1.1.1) and enable TLS 1.3 alongside TLS 1.2 in the server configuration.",
        ))

    summary = tls.get("cipher_summary") or {}
    if summary.get("weak", 0) > 0 or summary.get("insecure", 0) > 0:
        out.append(_r(
            SEVERITY_HIGH, "TLS", "Weak cipher suites accepted",
            f"{summary.get('weak', 0)} weak and {summary.get('insecure', 0)} insecure cipher suites are accepted. These include RC4, 3DES, DES, NULL or EXPORT ciphers.",
            "Restrict ciphers to modern AEAD suites, e.g. Nginx: `ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...; ssl_prefer_server_ciphers on;`. Use Mozilla's SSL Config Generator (intermediate profile).",
            "https://ssl-config.mozilla.org/",
        ))

    if summary.get("total", 0) > 0 and summary.get("forward_secrecy", 0) < summary.get("total", 0):
        out.append(_r(
            SEVERITY_MEDIUM, "TLS", "Forward secrecy not universal",
            "Some accepted cipher suites do not provide forward secrecy, so past sessions could be decrypted if the private key leaks.",
            "Only allow ECDHE/DHE based cipher suites. Disable static RSA key exchange.",
        ))

    if tls.get("tls_compression"):
        out.append(_r(
            SEVERITY_HIGH, "TLS", "TLS compression enabled (CRIME)",
            "TLS compression is enabled and leaves the server vulnerable to CRIME.",
            "Disable TLS compression. Nginx: already disabled by default. OpenSSL: compile with `-DOPENSSL_NO_COMP` or set `SSL_OP_NO_COMPRESSION`.",
        ))

    if not tls.get("ocsp_stapling"):
        out.append(_r(
            SEVERITY_LOW, "TLS", "OCSP stapling disabled",
            "Without OCSP stapling, clients may query the CA directly — slower and a privacy leak.",
            "Enable OCSP stapling. Nginx: `ssl_stapling on; ssl_stapling_verify on; resolver 1.1.1.1 valid=300s;`.",
        ))

    hsts = tls.get("hsts") or {}
    if not hsts.get("enabled"):
        out.append(_r(
            SEVERITY_MEDIUM, "TLS", "HSTS header missing",
            "Strict-Transport-Security is not set. A downgrade to plain HTTP is possible on first visit.",
            "Return `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on every HTTPS response. After testing, submit to hstspreload.org.",
            "https://hstspreload.org/",
        ))
    elif not hsts.get("preload"):
        out.append(_r(
            SEVERITY_INFO, "TLS", "HSTS not preload-ready",
            "HSTS is set but does not include `preload`.",
            "Add `preload` and `includeSubDomains` to the HSTS header and submit the domain to the preload list.",
            "https://hstspreload.org/",
        ))

    cert = tls.get("certificate") or {}
    if cert.get("expired"):
        out.append(_r(
            SEVERITY_CRITICAL, "Certificate", "Certificate expired",
            "The TLS certificate has expired. Browsers block access.",
            "Renew the certificate immediately. Automate renewal with ACME (Let's Encrypt + certbot / acme.sh).",
        ))
    elif cert.get("days_until_expiry") is not None and cert["days_until_expiry"] < 30:
        out.append(_r(
            SEVERITY_HIGH, "Certificate", "Certificate expires soon",
            f"Certificate expires in {cert['days_until_expiry']} days.",
            "Renew the certificate now and automate renewal to avoid future outages.",
        ))

    if cert.get("self_signed"):
        out.append(_r(
            SEVERITY_HIGH, "Certificate", "Self-signed certificate",
            "The certificate is self-signed. Browsers show warnings and APIs will refuse the connection.",
            "Obtain a certificate from a public CA (Let's Encrypt is free and automated).",
        ))

    return out


def _https_redirect(results):
    out = []
    red = results.get("https_redirect")
    if red and not red.get("pass"):
        out.append(_r(
            SEVERITY_HIGH, "Web", "HTTP does not redirect to HTTPS",
            "Plain HTTP traffic is not redirected to HTTPS, exposing users to MITM attacks.",
            "Force a 301 redirect from HTTP to HTTPS. Nginx: `return 301 https://$host$request_uri;`. Apache: `Redirect permanent / https://example.com/`.",
        ))
    elif red and red.get("pass") and not red.get("permanent"):
        out.append(_r(
            SEVERITY_LOW, "Web", "HTTPS redirect is temporary (302/307)",
            "The HTTP to HTTPS redirect uses a non-permanent status code.",
            "Use a permanent redirect (301 or 308) so browsers cache the redirect.",
        ))
    return out


_HEADER_FIX = {
    "Strict-Transport-Security": "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    "Content-Security-Policy": "Define a Content-Security-Policy. Start with `default-src 'self'` and tighten from there.",
    "X-Content-Type-Options": "Set `X-Content-Type-Options: nosniff`.",
    "X-Frame-Options": "Set `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.",
    "Referrer-Policy": "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
    "Permissions-Policy": "Define a `Permissions-Policy`, e.g. `geolocation=(), camera=(), microphone=()`.",
    "Cross-Origin-Opener-Policy": "Set `Cross-Origin-Opener-Policy: same-origin`.",
    "Cross-Origin-Resource-Policy": "Set `Cross-Origin-Resource-Policy: same-site` (or stricter).",
    "Cross-Origin-Embedder-Policy": "Set `Cross-Origin-Embedder-Policy: require-corp` if cross-origin isolation is required.",
    "X-XSS-Protection": "Set `X-XSS-Protection: 0` (modern browsers rely on CSP).",
}


def _headers(results):
    out = []
    headers = results.get("http_headers")
    if not headers or not headers.get("success"):
        return out
    missing = headers.get("headers_missing") or []
    if missing:
        severity = SEVERITY_MEDIUM if len(missing) >= 4 else SEVERITY_LOW
        out.append(_r(
            severity, "Web", f"{len(missing)} security header(s) missing",
            "The server does not send several recommended HTTP security headers.",
            "Add the following: " + "; ".join(_HEADER_FIX.get(h, f"Add `{h}`.") for h in missing),
            "https://owasp.org/www-project-secure-headers/",
        ))
    return out


def _ipv6(results):
    out = []
    ipv6 = results.get("ipv6")
    if ipv6 and not ipv6.get("has_ipv6"):
        out.append(_r(
            SEVERITY_LOW, "Network", "No IPv6 (AAAA) record",
            "The domain only resolves to IPv4. Clients on IPv6-only networks cannot reach it.",
            "Publish AAAA records that point to the IPv6 address of your web server and make sure the service listens on IPv6.",
        ))
    return out


def _blacklist(results):
    out = []
    bl = results.get("blacklist")
    if not bl:
        return out
    if bl.get("is_listed"):
        listed = ", ".join(bl.get("listed") or [])
        out.append(_r(
            SEVERITY_CRITICAL, "Network", "IP listed on DNSBL",
            f"The server IP is listed on: {listed}. Outbound mail will likely be blocked.",
            "Investigate potential compromise or spam sources. Request delisting on each DNSBL only after the root cause is fixed.",
        ))
    return out


RISKY_PORTS = {
    21: "FTP is unencrypted — use SFTP/FTPS instead.",
    23: "Telnet is unencrypted and deprecated — use SSH.",
    3306: "Database ports should not be public. Restrict with a firewall.",
    3389: "RDP is a common ransomware vector. Restrict to VPN or use a bastion.",
    5432: "Database ports should not be public. Restrict with a firewall.",
}


def _ports(results):
    out = []
    ports = results.get("ports")
    if not ports:
        return out
    for entry in ports.get("open") or []:
        port = entry.get("port")
        if port in RISKY_PORTS:
            out.append(_r(
                SEVERITY_HIGH, "Network", f"Risky port {port}/{entry.get('service')} is open",
                RISKY_PORTS[port],
                "Close the port on the public interface or restrict access via firewall/VPN.",
            ))
    return out


def _whois(results):
    out = []
    whois_data = (results.get("whois") or {}).get("data") or {}
    exp = whois_data.get("expiration_date")
    if isinstance(exp, list):
        exp = exp[0] if exp else None
    if isinstance(exp, str):
        try:
            from datetime import datetime, timezone
            parsed = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            days_left = (parsed - datetime.now(timezone.utc)).days
            if 0 <= days_left <= 30:
                out.append(_r(
                    SEVERITY_HIGH, "WHOIS", "Domain expires soon",
                    f"The domain registration expires in {days_left} days.",
                    "Renew the domain with your registrar and consider enabling auto-renew.",
                ))
            elif days_left < 0:
                out.append(_r(
                    SEVERITY_CRITICAL, "WHOIS", "Domain expired",
                    "The domain registration has expired.",
                    "Renew immediately; otherwise the domain may be released to another registrant.",
                ))
        except ValueError:
            pass
    return out


_SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}


def generate(results):
    """Return a sorted list of recommendations for a scan result dict."""
    recs = []
    for fn in (
        _whois, _dnssec, _spf, _dmarc, _dkim, _mta_sts, _tlsrpt,
        _tls, _https_redirect, _headers, _ipv6, _blacklist, _ports,
    ):
        try:
            recs.extend(fn(results) or [])
        except Exception:
            continue
    recs.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"], 99))
    return recs


def summarize_counts(recs):
    counts = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 0,
        SEVERITY_MEDIUM: 0,
        SEVERITY_LOW: 0,
        SEVERITY_INFO: 0,
    }
    for r in recs:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts
