#!/usr/bin/env python3 
"""
Herramienta multiplataforma de enumeración pasiva y activa.

Características
- Pasiva: crt.sh, Wayback Machine, lista de URLs por Google dork, opcional Wappalyzer mediante la CLI `webtech`
- Activa: resolución DNS mediante socket, nslookup, whois, opcional host, opcional Sublist3r, opcional DNSDumpster, opcional Gobuster/wfuzz

Notas
- Ejecutar únicamente contra objetivos para los que tengas autorización.
- Las herramientas externas son opcionales; el script detectará y omitirá las que no estén instaladas.
- Diseñado para funcionar en Windows, macOS y Linux cuando las herramientas están disponibles en PATH.
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

# Intentamos importar requests; si no está instalado, salimos con un mensaje de error.
try:
    import requests  # type: ignore
except Exception:
    print("[!] Este script requiere el paquete 'requests'. Instálalo con: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# Crea el directorio indicado (incluyendo padres) si no existe.
def ensure_directory(path: Path) -> None:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)


# Devuelve la ruta del ejecutable si existe en PATH (equivalente a `which`).
def which(command: str) -> Optional[str]:
    from shutil import which as shutil_which
    return shutil_which(command)


# Ejecuta un comando externo y devuelve (codigo_salida, stdout, stderr).
# Maneja timeout y excepciones para que el script no falle inesperadamente.
def run_command(command: List[str], timeout_seconds: int = 30) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        # Si se agota el tiempo, recuperamos lo que hubiera en stdout/stderr (si existe)
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, (bytes, bytearray)) else (exc.stderr or "")
        return 124, out, err
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


# Normaliza el dominio: quita espacios, lo pasa a minúsculas y elimina el punto final si lo tuviera.
def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = domain.rstrip(".")
    return domain


# Extrae dominios/subdominios de un texto usando una expresión regular basada en el dominio raíz.
def extract_domains_from_text(text: str, root_domain: str) -> Set[str]:
    pattern = re.compile(rf"([a-zA-Z0-9_-]+\.)*{re.escape(root_domain)}", re.IGNORECASE)
    return set(match.group(0).lower().rstrip(".") for match in pattern.finditer(text))


# Guarda una colección de líneas en un fichero, eliminando duplicados y ordenando.
def save_lines(path: Path, lines: Iterable[str]) -> None:
    unique = sorted(set(line.strip() for line in lines if line and line.strip()))
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in unique:
            f.write(line + "\n")


# Consulta crt.sh (JSON) para buscar certificados que incluyan el dominio.
# Guarda la respuesta cruda en raw_dir/crtsh.json y devuelve el conjunto de subdominios encontrados.
def passive_crtsh(domain: str, raw_dir: Path, timeout_seconds: int, insecure: bool) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(f"[*] Pasiva: crt.sh {url}")
    try:
        # Cuando se especifica --insecure, deshabilitamos la verificación TLS para crt.sh
        resp = requests.get(
            url,
            timeout=timeout_seconds,
            headers={"User-Agent": "enum.py/1.0"},
            verify=not insecure,
        )
        if resp.status_code != 200:
            print(f"[!] crt.sh devolvió estado {resp.status_code}")
            return set()
        text = resp.text
        raw_path = raw_dir / "crtsh.json"
        raw_path.write_text(text, encoding="utf-8")
        items = json.loads(text)
        results: Set[str] = set()
        for item in items:
            name_value = item.get("name_value", "")
            for sub in name_value.splitlines():
                sub = sub.strip().lower().rstrip(".")
                if sub and sub.endswith(domain):
                    results.add(sub)
        return results
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Error crt.sh: {exc}")
        return set()


# Consulta la Wayback Machine (CDX API) para obtener URLs archivadas y extraer dominios.
def passive_wayback(domain: str, raw_dir: Path, timeout_seconds: int) -> Set[str]:
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    print(f"[*] Pasiva: Wayback CDX {url}")
    try:
        resp = requests.get(url, timeout=timeout_seconds, headers={"User-Agent": "enum.py/1.0"})
        if resp.status_code != 200:
            print(f"[!] Wayback devolvió estado {resp.status_code}")
            return set()
        data = resp.json()
        raw_path = raw_dir / "wayback.json"
        raw_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        urls = [row[0] for row in data[1:]] if isinstance(data, list) and data else []
        joined = "\n".join(urls)
        return extract_domains_from_text(joined, domain)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Error Wayback: {exc}")
        return set()


# Crea una lista de URLs de búsqueda en Google (dorks) para investigar manualmente.
def google_dork_urls(domain: str) -> List[str]:
    queries = [
        f"site:{domain}",
        f"site:*.{domain}",
        f"site:*.{domain} -www.{domain}",
        f"site:{domain} inurl:login|admin|console",
        f"site:{domain} ext:bak|old|sql|env|ini|cfg|conf",
        f"site:{domain} intitle:index of",
    ]
    return [f"https://www.google.com/search?q={requests.utils.quote(q)}" for q in queries]


# Si está instalado, ejecuta la herramienta `webtech` (webtech/webtech-cli) para identificar tecnologías web.
def passive_wappalyzer(domain: str, raw_dir: Path, scheme: str, timeout_seconds: int) -> Optional[str]:
    exe = which("webtech")
    if not exe:
        print("[i] Omitiendo Wappalyzer/webtech: CLI 'webtech' no encontrada")
        return None
    url = f"{scheme}://{domain}"
    print(f"[*] Pasiva: webtech {url}")
    code, out, err = run_command([exe, "-u", url, "--json"], timeout_seconds=timeout_seconds)
    (raw_dir / "webtech.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "webtech.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] webtech terminó con {code}")
        return None
    return out


# Resolución simple mediante socket.gethostbyname_ex para obtener host/aliases.
def active_socket_resolve(domain: str) -> Set[str]:
    results: Set[str] = set()
    try:
        host, aliases, addrs = socket.gethostbyname_ex(domain)
        results.add(host)
        results.update(aliases)
    except Exception:
        pass
    return set(d for d in results if d.endswith(domain))


# Ejecuta nslookup (si existe) y extrae dominios de su salida.
def active_nslookup(domain: str, raw_dir: Path, timeout_seconds: int) -> Set[str]:
    exe = which("nslookup")
    if not exe:
        print("[i] Omitiendo nslookup: comando no encontrado")
        return set()
    print("[*] Activa: nslookup ANY")
    code, out, err = run_command([exe, "-type=ANY", domain], timeout_seconds=timeout_seconds)
    (raw_dir / "nslookup.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "nslookup.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] nslookup terminó con {code}")
    return extract_domains_from_text(out + "\n" + err, domain)


# Ejecuta la utilidad 'host' (si está disponible) y extrae dominios de su salida.
def active_host(domain: str, raw_dir: Path, timeout_seconds: int) -> Set[str]:
    exe = which("host")
    if not exe:
        print("[i] Omitiendo host: comando no encontrado")
        return set()
    print("[*] Activa: host -a")
    code, out, err = run_command([exe, "-a", domain], timeout_seconds=timeout_seconds)
    (raw_dir / "host.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "host.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] host terminó con {code}")
    return extract_domains_from_text(out + "\n" + err, domain)


# Ejecuta whois si está disponible y extrae dominios de su salida.
def active_whois(domain: str, raw_dir: Path, timeout_seconds: int) -> Set[str]:
    exe = which("whois")
    if not exe:
        print("[i] Omitiendo whois: comando no encontrado")
        return set()
    print("[*] Activa: whois")
    code, out, err = run_command([exe, domain], timeout_seconds=timeout_seconds)
    (raw_dir / "whois.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "whois.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] whois terminó con {code}")
    return extract_domains_from_text(out + "\n" + err, domain)


# Si el módulo Sublist3r está instalado, lo usa; si no, busca el ejecutable y lo ejecuta.
def active_sublist3r(domain: str, raw_dir: Path, timeout_seconds: int) -> Set[str]:
    print("[*] Activa: Sublist3r (si está disponible)")
    try:
        import sublist3r  # type: ignore
        results = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        subs = set(str(s).lower().strip() for s in results if str(s).lower().strip().endswith(domain))
        (raw_dir / "sublist3r.module.txt").write_text("\n".join(sorted(subs)), encoding="utf-8")
        return subs
    except Exception:
        pass
    exe = which("sublist3r")
    if not exe:
        print("[i] Omitiendo Sublist3r: no está instalado")
        return set()
    code, out, err = run_command([exe, "-d", domain, "-o", "-"], timeout_seconds=timeout_seconds)
    (raw_dir / "sublist3r.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "sublist3r.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] sublist3r terminó con {code}")
    return set(line.strip().lower() for line in out.splitlines() if line.strip().lower().endswith(domain))


# Usa la API de dnsdumpster si está disponible (módulo) y devuelve subdominios encontrados.
def active_dnsdumpster(domain: str, raw_dir: Path) -> Set[str]:
    print("[*] Activa: DNSDumpster (si está disponible)")
    try:
        from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI  # type: ignore
        api = DNSDumpsterAPI()
        data = api.search(domain)
        (raw_dir / "dnsdumpster.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        results: Set[str] = set()
        for entry in data.get("dns_records", {}).get("host", []) or []:
            name = str(entry.get("domain", "")).lower().strip().rstrip(".")
            if name.endswith(domain):
                results.add(name)
        return results
    except Exception:
        print("[i] Omitiendo DNSDumpster: módulo no disponible o fallo")
        return set()


# Ejecuta gobuster en modo DNS si está disponible y se ha proporcionado un wordlist.
def active_gobuster(domain: str, wordlist: Optional[str], raw_dir: Path, timeout_seconds: int) -> Set[str]:
    exe = which("gobuster")
    if not exe:
        print("[i] Omitiendo Gobuster: comando no encontrado")
        return set()
    if not wordlist:
        print("[i] Omitiendo Gobuster: proporciona --wordlist para habilitar")
        return set()
    print("[*] Activa: Gobuster modo DNS")
    code, out, err = run_command([exe, "dns", "-d", domain, "-w", wordlist, "-q"], timeout_seconds=timeout_seconds)
    (raw_dir / "gobuster.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "gobuster.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] gobuster terminó con {code}")
    subs = set()
    for line in out.splitlines():
        if not line.strip():
            continue
        part = line.split()[0].strip().lower()
        if part.endswith(domain):
            subs.add(part)
    return subs


# Ejecuta wfuzz para fuzzing basado en peticiones HTTP (si está disponible y hay wordlist).
def active_wfuzz(domain: str, wordlist: Optional[str], raw_dir: Path, timeout_seconds: int) -> Set[str]:
    exe = which("wfuzz")
    if not exe:
        print("[i] Omitiendo wfuzz: comando no encontrado")
        return set()
    if not wordlist:
        print("[i] Omitiendo wfuzz: proporciona --wordlist para habilitar")
        return set()
    print("[*] Activa: wfuzz subdomain fuzzing (basado en peticiones HTTP)")
    url = f"http://FUZZ.{domain}"
    code, out, err = run_command([
        exe,
        "-c",
        "-t","50",
        "-w", wordlist,
        "--hs","404",
        "-u", url,
    ], timeout_seconds=timeout_seconds)
    (raw_dir / "wfuzz.stdout.txt").write_text(out, encoding="utf-8")
    (raw_dir / "wfuzz.stderr.txt").write_text(err, encoding="utf-8")
    if code != 0:
        print(f"[!] wfuzz terminó con {code}")
    subs = set()
    for line in out.splitlines():
        match = re.search(r"\[\d+\]\s+([a-zA-Z0-9_-]+)\s+", line)
        if match:
            subs.add(f"{match.group(1).lower()}.{domain}")
    return subs


# Función principal: parsea argumentos, organiza directorios, ejecuta módulos pasivos y activos según flags.
def main() -> None:
    parser = argparse.ArgumentParser(description="Ayudante de enumeración pasiva y activa. Usar solo con autorización.")
    parser.add_argument("domain", help="Dominio raíz objetivo, p.ej. example.com")
    parser.add_argument("--output", "-o", default="outputs", help="Directorio de salida (por defecto: outputs)")
    parser.add_argument("--scheme", default="https", choices=["http", "https"], help="Esquema para comprobaciones web (por defecto: https)")
    parser.add_argument("--passive-only", action="store_true", help="Ejecutar solo enumeración pasiva")
    parser.add_argument("--active-only", action="store_true", help="Ejecutar solo enumeración activa")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en segundos para llamadas HTTP y comandos (por defecto: 30)")
    parser.add_argument("--insecure", action="store_true", help="Omitir verificación TLS para crt.sh (usar solo si es necesario)")
    parser.add_argument("--wordlist", help="Ruta al wordlist para Gobuster/wfuzz (opcional)")
    args = parser.parse_args()

    domain = normalize_domain(args.domain)
    output_dir = Path(args.output).resolve()
    raw_dir = output_dir / "raw"
    reports_dir = output_dir / "reports"
    ensure_directory(output_dir)
    ensure_directory(raw_dir)
    ensure_directory(reports_dir)

    print(f"[+] Objetivo: {domain}")
    print(f"[+] Salida: {output_dir}")

    run_passive = True
    run_active = True
    if args.passive_only and args.active_only:
        print("[!] --passive-only y --active-only son mutuamente excluyentes", file=sys.stderr)
        sys.exit(2)
    if args.passive_only:
        run_active = False
    if args.active_only:
        run_passive = False

    passive_subs: Set[str] = set()
    active_subs: Set[str] = set()

    start_time = time.time()

    if run_passive:
        print("\n=== Enumeración pasiva ===")
        # Opcionalmente deshabilita la verificación TLS para crt.sh cuando se especifica --insecure
        if args.insecure:
            try:
                import urllib3  # type: ignore
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        passive_subs |= passive_crtsh(domain, raw_dir, args.timeout, insecure=args.insecure)
        passive_subs |= passive_wayback(domain, raw_dir, args.timeout)
        dorks = google_dork_urls(domain)
        save_lines(output_dir / "google_dorks.txt", dorks)
        wapp_output = passive_wappalyzer(domain, raw_dir, args.scheme, args.timeout)
        if wapp_output:
            (raw_dir / "wappalyzer.webtech.json").write_text(wapp_output, encoding="utf-8")
        save_lines(output_dir / "domains_passive.txt", passive_subs)

    if run_active:
        print("\n=== Enumeración activa ===")
        active_subs |= active_socket_resolve(domain)
        active_subs |= active_nslookup(domain, raw_dir, args.timeout)
        active_subs |= active_host(domain, raw_dir, args.timeout)
        active_subs |= active_whois(domain, raw_dir, args.timeout)
        active_subs |= active_sublist3r(domain, raw_dir, args.timeout)
        active_subs |= active_dnsdumpster(domain, raw_dir)
        active_subs |= active_gobuster(domain, args.wordlist, raw_dir, max(args.timeout, 120))
        active_subs |= active_wfuzz(domain, args.wordlist, raw_dir, max(args.timeout, 120))
        save_lines(output_dir / "domains_active.txt", active_subs)

    all_subs = sorted(set(s for s in passive_subs | active_subs if s and s.endswith(domain)))
    save_lines(output_dir / "domains_all.txt", all_subs)

    summary_lines = [
        f"Objetivo: {domain}",
        f"Subdominios pasivos: {len(passive_subs)}",
        f"Subdominios activos: {len(active_subs)}",
        f"Todos los subdominios únicos: {len(all_subs)}",
        f"Duración: {time.time() - start_time:.1f}s",
        "",
        "Outputs:",
        f" - {output_dir / 'domains_passive.txt'}",
        f" - {output_dir / 'domains_active.txt'}",
        f" - {output_dir / 'domains_all.txt'}",
        f" - {output_dir / 'google_dorks.txt'}",
        f" - {raw_dir}",
    ]
    (reports_dir / "summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")

    print("\n=== Hecho ===")
    print("\n".join(summary_lines))


if __name__ == "__main__":
    main()
