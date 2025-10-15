## Guía de uso: capturador_ua.py

Este script permite:
- Obtener cabeceras de seguridad de URLs externas (modo `fetch`).
- Levantar un servidor HTTP local para capturar peticiones entrantes y registrar sus cabeceras (incluyendo `User-Agent`) en disco (modo `serve`).

### Requisitos
- Python 3.8+
- Librería `requests` (se instala con `pip install -r requirements.txt` o `pip install requests`)

### Modos de ejecución

1) Modo fetch (saliente):
   - El script realiza peticiones a URLs que tú indiques y guarda un JSON con todas las cabeceras de respuesta junto a un subconjunto de cabeceras de seguridad.
   - Ejemplo:
   ```bash
   python capturador_ua.py fetch --out headers.json --timeout 20 https://example.com https://httpbin.org/headers
   ```

2) Modo serve (entrante):
   - El script arranca un servidor HTTP local escuchando en un puerto (por defecto 8000). Cada petición que reciba se guarda en un fichero JSON.
   - Soporta dos formatos de salida:
     - `jsonl`: una línea JSON por petición (recomendado para logs continuos)
     - `json`: un único fichero con un array JSON que contiene todos los registros
   - Ejemplos:
   ```bash
   # JSONL (una línea por petición)
   python capturador_ua.py serve --port 8765 --out ua_capturas.jsonl --format jsonl --verbose

   # JSON (array de objetos)
   python capturador_ua.py serve --port 8765 --out ua_capturas.json --format json --verbose
   ```

   Además, el servidor sirve una página web simple en `/` y `/index.html`.
   - Si existe `index.html` en el mismo directorio del script, se devuelve ese fichero.
   - Si no existe, se devuelve una página mínima con botones de prueba (GET y POST).

### Estructura de cada registro (modo serve)
Cada petición entrante que se capture contiene, entre otros, estos campos:
- `timestamp`: momento UNIX de la captura
- `remote_addr`: IP del cliente
- `method`: método HTTP (GET/POST/...)
- `path`: ruta solicitada
- `headers`: diccionario de cabeceras recibidas
- `user_agent`: valor de la cabecera `User-Agent` (si está presente)
- `body_len`: tamaño del cuerpo de la petición (bytes)

### Uso con una página local (index.html)
Puedes utilizar el fichero `index.html` incluido para generar peticiones desde tu navegador hacia el servidor local y así capturar el User-Agent.

Pasos:
1. Arranca el servidor de captura en loopback (localhost):
   ```bash
   python capturador_ua.py serve --port 8765 --out ua_capturas.jsonl --format jsonl --verbose
   ```
2. Abre el `index.html` en tu navegador (doble clic o arrastrando el archivo al navegador). Alternativamente, sirve el HTML desde un servidor estático; no es obligatorio.
3. En la página, haz clic en el botón "Enviar beacon" o "Enviar POST" para lanzar peticiones hacia `http://127.0.0.1:8765/`.
4. Observa la terminal del servidor (verás un resumen de cada petición si usaste `--verbose`).
5. Revisa el fichero de salida (`ua_capturas.jsonl` o el que definiste) para ver las entradas con `user_agent` y demás campos.

Notas:
- El acceso desde otros dispositivos de tu red es posible si usan tu IP local (e.g., `http://TU_IP_LOCAL:8765/`) y tu firewall lo permite.
- Para exponer hacia Internet, podrías usar túneles como ngrok. En dicho caso, cualquier cliente que visite tu URL pública generará registros en tu fichero local.

### Comprobaciones rápidas con curl
```bash
curl -A "Mi-UserAgent/1.0" http://127.0.0.1:8765/test
curl -A "Mi-UserAgent/2.0" -H "Content-Type: application/json" -d '{"x":1}' http://127.0.0.1:8765/post
```

### Solución de problemas
- "El puerto ya está en uso": cambia el puerto con `--port` (por ejemplo, 8787).
- "No se generan entradas": asegúrate de que el cliente realmente hace peticiones a `http://127.0.0.1:PUERTO/`. Con `--verbose` deberías ver líneas en la terminal por cada petición.
- Firewall Windows: si aparece un aviso, permite a Python escuchar en la red privada. Si solo quieres loopback, normalmente no hace falta permiso adicional.
- PowerShell: para detener el servidor, usa Ctrl+C en la ventana donde lo arrancaste.

### Campos capturados de seguridad (modo fetch)
Cuando usas `fetch`, además de todas las cabeceras, se resaltan estas (si existen):
`content-security-policy`, `strict-transport-security`, `x-content-type-options`, `x-frame-options`, `x-xss-protection`, `referrer-policy`, `permissions-policy`, `cross-origin-opener-policy`, `cross-origin-embedder-policy`, `cross-origin-resource-policy`, `x-permitted-cross-domain-policies`, `server`.

### Ejecución resumida paso a paso (captura local de User-Agent)
1. Instala dependencias: `pip install -r requirements.txt`
2. Arranca el servidor: `python capturador_ua.py serve --port 8765 --out ua_capturas.jsonl --format jsonl --verbose`
3. Abre `index.html` y pulsa en los botones para enviar peticiones.
4. Revisa `ua_capturas.jsonl` para ver `user_agent` y demás metadatos de cada petición.


