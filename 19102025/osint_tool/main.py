# main.py
# Ejecuta la herramienta OSINT llamando a los módulos.
# Este archivo define la clase orquestadora `OSINTTool` y una CLI simple
# para ejecutar la recolección desde terminal.

from modules.whois_module import WhoisModule  # Consultas WHOIS del dominio
from modules.dns_module import DNSModule  # Resoluciones DNS comunes (A, MX, etc.)
from modules.meta_module import MetaModule  # Extrae metadatos HTML básicos del sitio
from modules.leakcheck_module import LeakCheckModule   # ✅ Chequea filtraciones por email
from modules.username_module import UsernameModule  # Lanza Sherlock para buscar username
from modules.name_search_module import NameSearchModule  # Busca enlaces relacionados al nombre
from modules.graph_builder import GraphBuilder  # Construye un grafo simple de relaciones
from modules.report_generator import ReportGenerator  # Genera reportes JSON/HTML
import argparse  # CLI
import pprint    # Impresión legible de resultados


class OSINTTool:
    """Clase principal que ejecuta los módulos OSINT y genera el reporte final.

    Recibe posibles insumos (nombre, email, username, teléfono y dominio) y,
    según cuáles estén presentes, ejecuta los módulos correspondientes.
    """

    def __init__(
        self,
        name=None,
        email=None,
        username=None,
        phone=None,
        domain=None,
        sherlock_path=None,
        output_basename="report"
    ):
        # Guardamos parámetros de entrada para decidir qué módulos ejecutar
        self.name = name
        self.email = email
        self.username = username
        self.phone = phone
        self.domain = domain
        self.sherlock_path = sherlock_path
        self.output_basename = output_basename
        self.results = {}  # Aquí se agregan los resultados por módulo

    def add_result(self, module_name, data):
        # Agrega/actualiza el resultado de un módulo por su nombre clave
        self.results[module_name] = data

    def run(self):
        """Ejecuta todos los módulos disponibles según entradas presentes."""
        if self.domain:
            # Cuando hay dominio: WHOIS, DNS y metadatos de la web
            self.add_result("whois", WhoisModule(self.domain).run())
            self.add_result("dns", DNSModule(self.domain).run())
            self.add_result("meta", MetaModule(self.domain).run())

        if self.email:
            # ✅ Email: consulta a LeakCheck (sustituto de HIBP)
            self.add_result("leakcheck", LeakCheckModule(self.email).run())

        if self.username:
            # Username: lanza Sherlock (si está instalado/en ruta)
            self.add_result("username_search", UsernameModule(self.username, self.sherlock_path).run())

        if self.name:
            # Nombre: busca enlaces relacionados vía la API de DuckDuckGo
            self.add_result("name_search", NameSearchModule(self.name).run())

        # Genera reportes JSON y HTML con todos los resultados
        rg = ReportGenerator(self.results, basename=self.output_basename)
        json_path = rg.save_json()
        html_path = rg.save_html()

        # Genera un grafo simple conectando módulos con sus subclaves
        gb = GraphBuilder(self.results)
        graph_path = gb.build(self.output_basename + "_graph.png")

        return {
            "results": self.results,
            "json": json_path,
            "html": html_path,
            "graph": graph_path
        }


def parse_args():
    # Define la interfaz de línea de comandos para ejecutar desde terminal
    p = argparse.ArgumentParser(description="OSINTTool - CLI")
    p.add_argument("--name", help="Full name to search")
    p.add_argument("--email", help="Email to search")
    p.add_argument("--username", help="Username to search")
    p.add_argument("--phone", help="Phone number to store")
    p.add_argument("--domain", help="Domain to analyze")
    p.add_argument("--sherlock-path", help="Path to sherlock executable (optional)")
    p.add_argument("--output", default="report", help="Output basename (report.json, report.html, etc.)")
    return p.parse_args()


if __name__ == "__main__":
    # Punto de entrada cuando se ejecuta `python main.py`
    args = parse_args()
    tool = OSINTTool(
        name=args.name,
        email=args.email,
        username=args.username,
        phone=args.phone,
        domain=args.domain,
        sherlock_path=args.sherlock_path,
        output_basename=args.output
    )
    out = tool.run()
    print("✅ Recolección completada. Archivos generados:")
    pprint.pprint(out)
