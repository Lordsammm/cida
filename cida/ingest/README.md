# Ingest

Converts raw assessment artefacts into `Finding` objects. Never looks at filenames - classifies every file by probing its internal structure.

```
sniffer.py       reads ~100 KB of each file, scores against 14 categories
findings.py      routes to the right parser

nessus.py        Nessus / Qualys / OpenVAS / Rapid7 / Metasploit
vapt_pdf.py      any VAPT PDF (pdfplumber + optional LLM assist)
attack_surface.py  Shodan / Censys / Amass / theHarvester / Recon-ng / BBOT
cspm_aws.py      AWS Prowler v3/v4 / Security Hub
cspm_azure.py    Azure Defender for Cloud / ScoutSuite
cspm_gcp.py      GCP Security Command Center / ScoutSuite
darkweb.py       SpyCloud / DeHashed / Hudson Rock / Flare / breach forums
dmarc.py         checkdmarc / hardenize / dmarcian
questionnaire.py CIDA platform CSV (yes/no, scale 1-5, evidence)
```

## Supported tools

**Vulnerability scanners** - Nessus, Qualys, OpenVAS/Greenbone, Rapid7 InsightVM, Metasploit, Tenable.io (`.nessus` / `.xml` / `.csv` / `.json`)

**Web app scanners** - Burp Suite, OWASP ZAP, Nikto, Acunetix, IBM AppScan, w3af (`.xml` / `.json`)

**Network scanners** - Nmap, Masscan, Zmap (`.xml` / `.csv`)

**Cloud CSPM**
| Tool | Cloud |
|------|-------|
| Prowler v3/v4, Security Hub | AWS |
| Defender for Cloud, ScoutSuite | Azure |
| Security Command Center, ScoutSuite | GCP |
| Wiz, Orca, Prisma Cloud | Multi |

**Attack surface / OSINT** - Shodan, Censys, Amass, theHarvester, Recon-ng, BBOT, Subfinder, Nuclei

**Dark web** - SpyCloud, DeHashed, Hudson Rock, Flare, HIBP, generic breach dumps (email+password CSV), stealer logs (RedLine, Raccoon, Vidar, Lumma)

**Email security** - checkdmarc, hardenize, dmarcian, mail-tester

**Other** - VAPT PDFs (`.pdf`), evidence screenshots (`.png` / `.jpg` / `.svg`), CIDA narrative reports (`.docx`), pre-normalised Finding JSON

## Adding a tool

1. Write a parser returning `list[Finding]`.
2. Add scoring signals to `sniffer.py`.
3. Add a dispatch case in `findings.py → load_findings_from_dir()`.
