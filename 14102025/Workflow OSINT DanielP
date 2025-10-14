# Daniel Pérez Bastante — Workflow Metodología OSINT

> **Entorno:** universitario y controlado  
> **Objetivo:** aplicar metodología OSINT, priorizando herramientas pasivas para dejar el menor rastro posible.
> **Nota:** Se priorizará respetar la legalidad, el RGPD y las normas éticas de la investigación digital.

---

## Fases y workflow

### 1️. Definición de objetivo  
**¿Qué queremos saber y por qué?**

- Primero identificar:
  - **Quién** es el sujeto/objeto (persona, empresa, servicio, infraestructura) a investigar.
  - **Qué** datos concretos buscamos (contacto, relaciones, infraestructura, historial público…).
  - **Alcance**: geográfico, temporal y temático.
  - **Limitaciones legales y éticas**: qué está permitido y que se investigue y qué no.

**Plantillas / ayudas:**  
- Checklist de planificación (p. ej. frameworks OSINT)  
- Documentos de requisitos o briefings  

**Herramientas recomendadas:**  
- Plantillas de planificación

---

### 2️. Reconocimiento y enumeración de fuentes  
**Identificar las fuentes potenciales.**

- Tipos de fuentes:
  - Motores de búsqueda (Google, Bing, Yandex)
  - Redes sociales (LinkedIn, Instagram, X, Facebook)
  - Registros públicos (mercantiles, profesionales, etc.)
  - WHOIS / DNS / certificados SSL
  - Archivos históricos, foros y pastebins públicos

**Herramientas recomendadas a utilizar:**  
- [OSINT Framework](https://osintframework.com/) → **Herramienta pasiva**  
- [IntelTechniques](https://inteltechniques.com/) → **Herramienta pasiva**  
- WHOIS / WhoisIP → **Herramienta pasiva**  
- Google Dorks → **Herramienta pasiva**  
- Shodan → **Herramienta moderada**  
- Censys → **Herramienta moderada**  
- Numverify → **Herramienta pasiva**  
- Truecaller → **Herramienta pasiva**  
- Google / LinkedIn (para ver presencia profesional o pública) → **Herramientas pasivas**  
- Spokeo → **Herramienta moderada**

---

### 3️. Recolección de información  
**Obtener datos crudos de forma sistemática.**

- Técnicas:
  - Búsquedas booleanas y dorks
  - Archivo de páginas web (para preservación)
  - Extracción de metadatos y contenidos públicos
  - Web scraping **sólo si está permitido**
  - Búsqueda inversa de imágenes (para relacionar perfiles o localizar contenido)

**Herramientas (por tipo):**  
- Google Dorks → **Herramienta pasiva**  
- TheHarvester (emails / subdominios) → **Herramienta moderada**  
- SpiderFoot (automatización) → **Herramienta pasiva**  
- Metagoofil / FOCA (metadatos de documentos) → **Herramientas pasivas**  
- Wayback Machine / Archive.today → **Herramientas pasivas**  
- Hunter.io (emails y dominios) → **Herramienta moderada**  
- Twint (X/Twitter sin API, solo si es legalmente válido) → **Herramienta moderada**  
- Búsqueda inversa de imágenes (Google, Yandex, TinEye) → **Herramientas pasivas**

*Nota importante: Debe evitarse cualquier intento de autenticación o acceso no autorizado.*

---

### 4️. Análisis de la información  
**Conectar puntos, identificar patrones y evaluar veracidad de las pruebas.**

- Objetivos:
  - Relacionar entidades (personas, dominios, correos, ubicaciones, etc)
  - Identificar vínculos, patrones o inconsistencias
  - Priorizar hallazgos según la fiabilidad (por ejemplo, una información de un puesto de trabajo actual en Linkedin va a ser más fiable que un twit del 2013)

**Herramientas:**  
- Maltego (visualización relacional) → **Herramienta moderada**  
- Sherlock (alias en redes sociales) → **Herramienta pasiva**  
- Obsidian / Logseq (red de conocimiento personal) → **Herramientas pasivas**  
- Neo4j / Gephi (análisis de grafos) → **Herramientas pasivas**  
- Lampyre / Paliscope → **Herramientas moderadas**  

---

### 5️. Validación y corroboración  
**Confirmar que los datos son fiables.**

- Triangular la información en múltiples fuentes  
- Verificar procedencia, la fecha y el contexto  
- Analizar imágenes y vídeos (geolocalización, sombras, metadatos)

**Herramientas:**  
- Google Reverse Image / Yandex / TinEye → **Herramientas pasivas**  
- InVID / WeVerify → **Herramientas moderadas**  
- ExifTool → **Herramienta pasiva**  
- FotoForensics → **Herramienta moderada**  
- SunCalc.org → **Herramienta pasiva**  
- IP Geolocation → **Herramienta pasiva**  
- Google Maps (para confirmar ubicaciones o coincidencias visuales) → **Herramienta pasiva** 

---

### 6️. Documentación e informe  
**Crear un informe útil, claro y replicable.**

- Incluir:
  - Resumen ejecutivo con hallazgos clave  
  - Metodología utilizada y fuentes 
  - Evidencias (capturas, URLs archivadas, fechas)
  - Limitaciones y riesgos

**Herramientas:**  
- Markdown + Obsidian 
- Word y/o PDF  
- Wayback Machine si fuese necesario  
- Hunchly (documentación automática) -> **Puede dejar algo de huella, semipasiva** 

---

### 7️. Evaluación legal y ética  
**Asegurar cumplimiento normativo y proporcionalidad.**

- Revisa:
  - RGPD y leyes locales de privacidad  
  - No realizar acciones que impliquen acceso no autorizado  
  - Proporcionalidad: recolectar solo lo necesario  
  - Consentimiento explícito cuando corresponda  

**Referencias:**  
- RGPD (UE)  
- Manuales éticos OSINT (Bellingcat, OSINT Curious)  
- Normas de privacidad locales

---

## Workflow visual por pasos

```plaintext
[1] Definir objetivo
    ↓
[2] Identificar fuentes
    ↓
[3] Recolectar datos (automatizada + manual) 
    ↓
[4] Analizar datos (relaciones, patrones)
    ↓
[5] Validar datos (triangulación, verificación)
    ↓
[6] Documentar e informar
    ↓
[7] Evaluar ética y legalidad

