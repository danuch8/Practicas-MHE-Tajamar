-Comprobación de brechas, revisión usernames, RRSS y metadatos de nombres asociados
-Integración con Sherlock
-Reporte en PDF, JSON o HTML
-Correlacionar datos relacionados (edad, residencia, etc)
-Visualizar conexiones con un grupo de relaciones, como **Maltego**
-**Importante**: Mirar *triggers* de la gente, como su alineación política

+Recopilación pasiva y activa: 
Diferencia principal: La recopilación pasiva no hace **ruido** y no deja rastro (a lo sumo logs), mientras que la la recopilación Activa siempre deja rastro y es fácil de detectar

-Fase 1. **Planning**: Objetivos, Alcance, Registrar la Información, Consideraciones legales/éticas, selección de fuentes.
-Fase 2. **Recolección**: Ejecución, Métodos, Herramientas y Organización (diseño estructurado)
-Fase 3. **Procesamiento**, Interpretación, Correlación, Evaluación, Síntesis
-Fase 4. **Comunicación** de forma clara y concisa, Audiencia, (adaptar el informe en función de la audiencia), Accionable (que sea útil y permita tomar decisiones), Formato y Feedback

+Aspectos legales:
Siempre regirse por las Leyes de Protección de Datos (GDPR, LPD...) y tener en cuenta qué información pública podemos utilizar y qué no (nada de contraseñas filtradas, información bancaria, etc)

+Enumeración pasiva:
Por motivos de privacidad, la ICAN o IANA prohíbe que pueda verse el correo en WHOIS.
Herramientas: ~~WhoIS, DNSDumpster~~, Sublister o crt.sh, urlscan.io, shodan, dorks como intext:"Eduardo Hernández Jasopa" o site:asterisco.tesla.com. Wappalizer, que es una extensión pasiva muestra tecnologías.
Los bots hacen scraping de user-agent

+Enumeración activa:
Herramientas como WHOIS, DNSdumpster, regresshion, sublister (ejemplo de uso: sublist3r -d kali.org -t 3 -e bing), wfuzz o gobuster, fuzzing (uso: coger subdominio, una lista o string suyo, y hacer mutaciones/cambios) y tecnologías Fingerprinting como nmap o whatweb, 

-**Importante**: DNSdumpster y WHOIS son **activos**, no pasivos.


+OSINT e Ingeniería social:
Construir una imagen con los datos de la persona (gustos, aficiones, intereses, etc), Recolectar datos como nombre, apellidos, nicknames, y huella digital en RRSS (Facebook, LinkedIn, Instagram, etc), usar técnicas como spokeo, y técnicas de enumeración como WhatsMyName, Sherlock o Google Dorking, Estenografía, mirar el end of file y least significant bit. Búsqueda inversa de imagen. WayBackMachine muy útil para contrastar con info pasada ya no visible. Para metadatos, ExifTool.
Maltego para conectar información, Spiderfoot.
Hay gente que patenta cosas para que si luego alguien quiere crear esa herramienta, tenga que pagar. Terrafacto Red Team. Truecaller para nums tlf. Para ingeniería inversa, **dehashed** (pero es de pago.)









