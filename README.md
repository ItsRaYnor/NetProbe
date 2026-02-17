# NetProbe

Domain Intelligence Toolkit — een lokale webtool voor snelle domeinanalyse, vergelijkbaar met MX Toolbox en internet.nl.

## Features

- **WHOIS Lookup** — Registrar, aanmaakdatum, vervaldatum, nameservers, status
- **DNS Records** — A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, PTR
- **DNSSEC Validatie** — Controle op DNSKEY en DS records
- **SPF Check** — Sender Policy Framework analyse met policy-beoordeling
- **DMARC Check** — Domain-based Message Authentication, policy-evaluatie
- **DKIM Check** — Controle op veelgebruikte DKIM selectors
- **MTA-STS** — Mail Transfer Agent Strict Transport Security detectie
- **TLS-RPT** — TLS Reporting configuratie check
- **SSL/TLS Certificaat** — Certificaatdetails, verloopdatum, cipher, SAN
- **HTTP Security Headers** — Controle op HSTS, CSP, X-Frame-Options, Referrer-Policy, etc.
- **HTTPS Redirect** — Controle of HTTP correct doorverwijst naar HTTPS
- **IPv6 Support** — AAAA records voor web, mail en nameservers
- **Blacklist Check (DNSBL)** — Controle op 8 veelgebruikte DNS blacklists
- **Port Scanner** — Scan van 17 veelgebruikte poorten (FTP, SSH, SMTP, HTTP, etc.)
- **Security Score Overview** — Visueel overzicht van alle checks met pass/fail status

## Vereisten

- Python 3.10+
- pip

## Installatie

```bash
# Clone de repository
git clone https://github.com/ItsRaYnor/NetProbe.git
cd NetProbe

# Maak een virtual environment aan (aanbevolen)
python -m venv venv

# Activeer het virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Installeer dependencies
pip install -r requirements.txt
```

## Gebruik

```bash
python app.py
```

Open vervolgens je browser en ga naar: **http://127.0.0.1:5000**

Voer een domeinnaam in (bijv. `example.com`) en klik op **Scan**. Je kunt kiezen welke checks je wilt uitvoeren, of alles tegelijk laten draaien.

## Projectstructuur

```
NetProbe/
├── app.py                  # Flask backend met alle checks
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # HTML frontend
└── static/
    ├── css/
    │   └── style.css       # Styling (dark theme)
    └── js/
        └── app.js          # Frontend logica
```

## Screenshots

Na het starten van de applicatie zie je een donker dashboard met:
- Zoekbalk bovenaan om een domein in te voeren
- Checkboxes om specifieke checks te selecteren
- Tabbladen voor WHOIS, DNS, E-mail Security, SSL/TLS, Web Security en Network
- Een score-overzicht met pass/fail badges per check

## API

De tool biedt een REST API:

### POST `/api/scan`

```json
{
  "domain": "example.com",
  "checks": ["all"]
}
```

Beschikbare checks: `whois`, `dns`, `dnssec`, `spf`, `dmarc`, `dkim`, `mta_sts`, `tlsrpt`, `ssl`, `http_headers`, `https_redirect`, `ipv6`, `blacklist`, `ports`, `all`

### POST `/api/reverse-dns`

```json
{
  "ip": "8.8.8.8"
}
```

## Licentie

MIT License — zie [LICENSE](LICENSE) voor details.
