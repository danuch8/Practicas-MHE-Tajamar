## Asistente de enumeración (pasiva + activa)

Script en Python para ejecutar reconocimiento pasivo y activo contra un dominio raíz. Usar únicamente con autorización.

### Características
- Pasiva: crt.sh, Wayback Machine, lista de URLs por Google dork, Wappalyzer opcional mediante la CLI webtech.
- Activa: resolución DNS, nslookup, whois, host opcional, Sublist3r opcional, DNSDumpster opcional, Gobuster/wfuzz opcionales.

### Requisitos
- Python 3.8+
- `pip install -r requirements.txt` (instala `requests`)
- Herramientas opcionales en el PATH para funcionalidades extra:
  - `webtech`, `sublist3r`, `gobuster`, `wfuzz`, `nslookup` (OS), `host` (bind9), `whois`
  - Python modules: `dnsdumpster`, `sublist3r`

### Uso
```bash
python fingerprinting.py example.com -o outputs
```
- Por ejemplo: python fingerprinting.py example.com --passive-only --insecure

Opciones:
- `--passive-only` or `--active-only`
- `--scheme http|https` (usado para `webtech`)
- `--timeout <seconds>` (por defecto 30)
- `--wordlist <path>` habilita fuerza bruta DNS con Gobuster/wfuzz
- `--insecure` omite la verificación TLS solo para crt.sh (usar cuando una inspección corporativa mitm bloquea SSL)

Outputs (creados bajo `-o outputs`):
- `domains_passive.txt`, `domains_active.txt`, `domains_all.txt`
- `google_dorks.txt` (consultas clicables)
- `raw/` (salidas de comandos y JSON)
- `reports/summary.txt`

### Notas para Windows
- Asegúrate de que las herramientas opcionales estén disponibles en el PATH o instálalas mediante gestores de paquetes (p. ej. winget/choco/scoop). El script omitirá las herramientas que falten.

### Legal
Usar solo contra objetivos para los que tengas autorización.