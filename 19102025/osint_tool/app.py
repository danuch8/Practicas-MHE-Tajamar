from flask import Flask, render_template, request, send_from_directory, jsonify
import os
from main import OSINTTool

# app.py
# Servidor web mínimo con Flask para ofrecer una interfaz HTML
# que ejecute la herramienta OSINT y muestre resultados.

app = Flask(__name__, static_folder="static", template_folder="templates")


@app.route("/")
def index():
    # Renderiza la página principal con el formulario
    return render_template("index.html")


@app.route("/run", methods=["POST"]) 
def run_osint():
    # Recoge datos del formulario y ejecuta la orquestación
    name = request.form.get("name") or None
    email = request.form.get("email") or None
    username = request.form.get("username") or None
    domain = request.form.get("domain") or None
    output = request.form.get("output") or "report"

    tool = OSINTTool(
        name=name,
        email=email,
        username=username,
        domain=domain,
        output_basename=output,
    )

    results = tool.run()
    # Devolvemos JSON con rutas a archivos generados y resultados en crudo
    return jsonify(results)


@app.route("/files/<path:filename>")
def download_file(filename):
    # Sirve archivos generados (JSON/HTML/PNG) desde el directorio del proyecto
    directory = os.path.abspath(os.getcwd())
    return send_from_directory(directory, filename, as_attachment=False)


if __name__ == "__main__":
    # Levanta el servidor en localhost para uso local
    app.run(host="127.0.0.1", port=5000, debug=True)


