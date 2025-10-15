#!/usr/bin/env python3
"""
Recolector de cabeceras de seguridad y servidor local de captura.

Modos:
- Fetch: solicita una o más URLs y exporta cabeceras de respuesta (enfocado en cabeceras de seguridad) a JSON.
- Serve: inicia un servidor HTTP local que registra las cabeceras de cada petición (incluida User-Agent) en JSON.

Ejemplos:
- Modo fetch (por ejemplo, hacia tus URLs de RequestBin/Ngrok):
  python capturador_ua.py fetch --out headers.json https://example.ngrok.io https://en123.requestbin.com/abc

- Modo serve (captura peticiones entrantes, por ejemplo, con ngrok http 8000):
  python capturador_ua.py serve --port 8000 --out captures.jsonl
"""

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

try:
    import requests  # type: ignore
except Exception:
    # Dependencia necesaria para el modo fetch
    print("[!] Requiere 'requests'. Instálalo con: pip install requests", file=sys.stderr)
    sys.exit(1)

SECURITY_HEADER_KEYS = {
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "x-permitted-cross-domain-policies",
    "server",
}


def write_json(path: Path, data: Any) -> None:
    """Escribe un objeto Python como JSON formateado en disco."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Normaliza claves de cabeceras a minúsculas para comparaciones case-insensitive."""
    return {k.lower(): v for k, v in headers.items()}


def extract_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Extrae únicamente las cabeceras consideradas de seguridad de un diccionario de cabeceras."""
    h = normalize_headers(headers)
    return {k: h[k] for k in SECURITY_HEADER_KEYS if k in h}


def fetch_headers(urls: List[str], timeout: int) -> List[Dict[str, Any]]:
    """Solicita cada URL y devuelve un listado de registros con cabeceras y metadatos."""
    results: List[Dict[str, Any]] = []
    session = requests.Session()
    session.headers.update({"User-Agent": "security_headers.py/1.0"})
    for url in urls:
        record: Dict[str, Any] = {
            "url": url,
            "timestamp": time.time(),
            "ok": False,
            "status_code": None,
            "security_headers": {},
            "all_headers": {},
            "error": None,
        }
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            record["ok"] = True
            record["status_code"] = resp.status_code
            record["all_headers"] = dict(resp.headers)
            record["security_headers"] = extract_security_headers(dict(resp.headers))
        except Exception as exc:
            record["error"] = str(exc)
        results.append(record)
    return results


class CaptureHandler(BaseHTTPRequestHandler):
    """Manejador de peticiones que captura cabeceras y las persiste en disco.

    Atributos de clase (configurados al iniciar el servidor):
    - out_file: ruta del fichero de salida
    - verbose: si es True, imprime un resumen por cada petición
    - output_format: 'jsonl' o 'json'
    """
    out_file: Path
    verbose: bool
    output_format: str

    def _read_body(self) -> bytes:
        """Lee el cuerpo de la petición respetando Content-Length si existe."""
        length = 0
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except Exception:
            length = 0
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _capture(self) -> None:
        """Construye el registro de la petición y lo persiste en JSONL o JSON."""
        try:
            body = self._read_body()
            headers_dict = {k: v for k, v in self.headers.items()}
            record = {
                "timestamp": time.time(),
                "remote_addr": self.client_address[0] if self.client_address else None,
                "method": self.command,
                "path": self.path,
                "headers": headers_dict,
                "user_agent": headers_dict.get("User-Agent"),
                "body_len": len(body),
            }
            if self.output_format == "jsonl":
                # Añade una línea por registro (formato JSONL), ideal para streams.
                with self.out_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            else:
                # Formato JSON (array). Carga el fichero si existe, añade y reescribe.
                if self.out_file.exists():
                    try:
                        existing = json.loads(self.out_file.read_text(encoding="utf-8") or "[]")
                        if not isinstance(existing, list):
                            existing = []
                    except Exception:
                        existing = []
                else:
                    existing = []
                existing.append(record)
                write_json(self.out_file, existing)
            if self.verbose:
                ua = record["user_agent"] or "-"
                print(f"[+] {self.command} {self.path} UA={ua} len={record['body_len']}")
        except Exception as exc:
            print(f"[!] Capture error: {exc}", file=sys.stderr)

    def _respond(self, code: int = 200, body: str = "OK\n") -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _respond_html(self, code: int, html: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _serve_index(self) -> None:
        """Sirve index.html desde el mismo directorio del script; si no existe, sirve un HTML mínimo."""
        root = Path(__file__).resolve().parent
        index_path = root / "index.html"
        if index_path.exists():
            try:
                html = index_path.read_text(encoding="utf-8")
                self._respond_html(200, html)
                return
            except Exception as exc:
                print(f"[!] Error leyendo index.html: {exc}", file=sys.stderr)
        # Fallback sencillo con botones
        html = (
            "<!doctype html><html lang=\"es\"><meta charset=\"utf-8\">"
            "<title>capturador_ua</title><body>"
            "<h1>capturador_ua</h1>"
            "<p>Botones de prueba contra este servidor.</p>"
            "<button onclick=\"fetch('/beacon?_='+Date.now()).then(()=>alert('GET enviado'))\">Enviar beacon (GET)</button>"
            "<button onclick=\"fetch('/post',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({demo:true,ts:Date.now()})}).then(()=>alert('POST enviado'))\">Enviar POST</button>"
            "</body></html>"
        )
        self._respond_html(200, html)

    def do_GET(self) -> None:
        # Sirve index.html en / o /index.html; en el resto captura
        parsed_path = urlparse(self.path).path
        if parsed_path in ("/", "/index.html"):
            self._serve_index()
            return
        self._capture()
        self._respond(200, "Captured GET\n")

    def do_POST(self) -> None:
        self._capture()
        self._respond(200, "Captured POST\n")

    def do_PUT(self) -> None:
        self._capture()
        self._respond(200, "Captured PUT\n")

    def do_DELETE(self) -> None:
        self._capture()
        self._respond(200, "Captured DELETE\n")

    def log_message(self, format: str, *args: Any) -> None:
        # Silenciamos el logging por defecto; usamos 'verbose' para salida controlada
        return


def run_server(port: int, out: Path, verbose: bool, output_format: str) -> None:
    """Arranca un servidor HTTP que captura peticiones y persiste cabeceras."""
    CaptureHandler.out_file = out
    CaptureHandler.verbose = verbose
    CaptureHandler.output_format = output_format
    server = HTTPServer(("0.0.0.0", port), CaptureHandler)
    print(f"[+] Capture server listening on http://0.0.0.0:{port} -> {out} ({output_format})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Obtiene cabeceras de seguridad y/o ejecuta un servidor local de captura.")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_fetch = sub.add_parser("fetch", help="Obtiene cabeceras desde URLs")
    p_fetch.add_argument("urls", nargs="+", help="Una o más URLs (p.ej., tu URL de ngrok/RequestBin)")
    p_fetch.add_argument("--out", "-o", default="headers.json", help="Fichero de salida JSON (por defecto: headers.json)")
    p_fetch.add_argument("--timeout", type=int, default=20, help="Timeout HTTP en segundos (por defecto: 20)")

    p_serve = sub.add_parser("serve", help="Inicia un servidor HTTP local de captura")
    p_serve.add_argument("--port", "-p", type=int, default=8000, help="Puerto de escucha (por defecto: 8000)")
    p_serve.add_argument("--out", "-o", default="captures.jsonl", help="Fichero de salida JSON(L) (por defecto: captures.jsonl)")
    p_serve.add_argument("--format", choices=["jsonl", "json"], default="jsonl", help="Formato de salida: jsonl o json (por defecto: jsonl)")
    p_serve.add_argument("--verbose", action="store_true", help="Imprime un resumen por petición")

    args = parser.parse_args()

    if args.mode == "fetch":
        results = fetch_headers(args.urls, args.timeout)
        write_json(Path(args.out), results)
        # Resumen rápido en consola
        for r in results:
            url = r["url"]
            ok = r["ok"]
            sc = r["status_code"]
            sec = r["security_headers"]
            print(f"[fetch] {url} ok={ok} status={sc} keys={sorted(sec.keys())}")
        print(f"[+] Wrote {len(results)} entries to {args.out}")
        return

    if args.mode == "serve":
        run_server(args.port, Path(args.out), args.verbose, args.format)
        return


if __name__ == "__main__":
    main()