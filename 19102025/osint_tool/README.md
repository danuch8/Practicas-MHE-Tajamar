# OSINTTool

un framework modular basado en Python diseñado para automatizar la recopilación de inteligencia de fuentes abiertas (OSINT) sobre dominios, correos electrónicos, nombres de usuario y nombres reales.

## Archivos y Estructura

OSINTTool está organizado en una arquitectura modular, lo que permite una fácil expansión y mantenimiento.
```
osint_tool/
│
├── main.py                    
├── requirements.txt           
├── modules/                   
│   ├── dns_module.py
│   ├── graph_builder.py
│   ├── leakcheck_module.py
│   ├── meta_module.py
│   ├── name_search_module.py
│   ├── report_generator.py
│   ├── username_module.py
│   └── whois_module.py
├── report.html             
├── report.json               
├── report_graph.png        
└── sherlock/                 
```

## Funcionalidades Principales

-  **Análisis de dominios** → WHOIS, DNS y extracción de metadatos web
-  **Búsqueda de filtraciones de correos** → Verifica exposiciones mediante la API de LeakCheck
-  **Búsqueda de nombres de usuario** → Integración con Sherlock para búsquedas multiplataforma
- **Inteligencia de nombres reales** → Obtiene perfiles públicos usando la API de DuckDuckGo
-  **Reportes automatizados** → Exporta a JSON, HTML y genera gráficos de relaciones
-  **Arquitectura modular** → Cada función está contenida en un módulo independiente para facilitar actualizaciones

