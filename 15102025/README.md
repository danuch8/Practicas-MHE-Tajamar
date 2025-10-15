## Enumeration helper (passive + active)

Python script to run passive and active recon against a root domain. Use only with authorization.

### Features
- Passive: crt.sh, Wayback Machine, Google dork URL list, optional Wappalyzer via `webtech` CLI
- Active: DNS resolve, `nslookup`, `whois`, optional `host`, optional Sublist3r, optional DNSDumpster, optional Gobuster/wfuzz

### Requirements
- Python 3.8+
- `pip install -r requirements.txt` (installs `requests`)
- Optional tools on PATH for extra modules:
  - `webtech`, `sublist3r`, `gobuster`, `wfuzz`, `nslookup` (OS), `host` (bind9), `whois`
  - Python modules: `dnsdumpster`, `sublist3r`

### Usage
```bash
python fingerprinting.py example.com -o outputs
```
- For example: python fingerprinting.py example.com --passive-only --insecure

Options:
- `--passive-only` or `--active-only`
- `--scheme http|https` (used for `webtech`)
- `--timeout <seconds>` (default 30)
- `--wordlist <path>` enable Gobuster/wfuzz DNS brute force
- `--insecure` skip TLS verification only for crt.sh (use when corporate MITM blocks SSL)

Outputs (created under `-o outputs`):
- `domains_passive.txt`, `domains_active.txt`, `domains_all.txt`
- `google_dorks.txt` (clickable queries)
- `raw/` (command outputs and JSON)
- `reports/summary.txt`

### Windows notes
- Ensure optional tools are available in PATH or install via package managers (e.g., winget/choco/scoop). The script will skip missing tools.

### Legal
Only use against targets you are authorized to test.