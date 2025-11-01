#!/bin/bash

###############################################################################
# Vulnerabilidad Orchestrator
# Orquestador automático de herramientas de seguridad para análisis local
# Autor: Generated Script
# Uso: ./vuln_orchestrator.sh <IP_TARGET>
###############################################################################

set -uo pipefail

# Configuración de manejo de errores
set +e  # No salir automáticamente en errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables de configuración
TARGET="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="${OUTPUT_DIR}/report_${TIMESTAMP}.txt"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
NMAP_OPTIONS="-sV -sC -p- --open"
PORTS_LIST_FILE="${OUTPUT_DIR}/open_ports_${TIMESTAMP}.txt"
PORTS_CSV_FILE="${OUTPUT_DIR}/open_ports_${TIMESTAMP}.csv"

# Estructura de datos para servicios
declare -A SERVICES
declare -A VERSIONS
declare -A CVES
declare -A EXPLOITS
declare -A SHODAN_INFO

###############################################################################
# Funciones de utilidad
###############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_exploit() {
    echo -e "${MAGENTA}[EXPLOIT]${NC} $1"
}

check_dependencies() {
    log_info "Verificando dependencias..."
    
    local missing_deps=()
    local optional_deps=()
    
    # Dependencias obligatorias
    command -v nmap &> /dev/null || missing_deps+=("nmap")
    command -v searchsploit &> /dev/null || missing_deps+=("searchsploit")
    command -v curl &> /dev/null || missing_deps+=("curl")
    
    # Dependencias opcionales
    command -v jq &> /dev/null || optional_deps+=("jq")
    command -v xmllint &> /dev/null || optional_deps+=("xmllint")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Faltan las siguientes dependencias OBLIGATORIAS: ${missing_deps[*]}"
        log_error "Por favor instálalas antes de continuar"
        exit 1
    fi
    
    if [ ${#optional_deps[@]} -ne 0 ]; then
        log_warning "Dependencias opcionales no encontradas: ${optional_deps[*]}"
        log_warning "Algunas funciones pueden estar limitadas. Se recomienda instalarlas:"
        log_warning "  sudo apt install -y ${optional_deps[*]}"
    fi
    
    if [ -z "$SHODAN_API_KEY" ]; then
        log_warning "SHODAN_API_KEY no está configurada. Algunas funciones pueden estar limitadas."
    fi
    
    log_success "Dependencias obligatorias verificadas"
}

init_directories() {
    log_info "Inicializando directorios de salida..."
    mkdir -p "${OUTPUT_DIR}"
    log_success "Directorio de salida: ${OUTPUT_DIR}"
}

print_banner() {
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════╗
    ║          VULNERABILITY ORCHESTRATOR - Security Tool          ║
    ║              Análisis Automatizado de Seguridad              ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
}

usage() {
    cat << EOF
Uso: $0 <IP_TARGET>

Argumentos:
    IP_TARGET    Dirección IP del objetivo a analizar

Ejemplos:
    $0 192.168.1.100
    $0 10.0.0.50

Nota: Este script está diseñado únicamente para entornos controlados locales.
EOF
    exit 1
}

###############################################################################
# Funciones de escaneo nmap
###############################################################################

nmap_scan() {
    local target="$1"
    local output_file="${OUTPUT_DIR}/nmap_scan_${TIMESTAMP}.xml"
    
    log_info "Iniciando escaneo completo de nmap en ${target}..."
    log_info "Esto puede tardar varios minutos..."
    log_info "Opciones: $NMAP_OPTIONS"
    
    # Ejecutar nmap y capturar stderr para debugging
    local nmap_log="${OUTPUT_DIR}/nmap_scan_${TIMESTAMP}.log"
    log_info "Ejecutando nmap..."
    nmap $NMAP_OPTIONS -oX "${output_file}" "${target}" > "$nmap_log" 2>&1
    local nmap_exit=$?
    
    if [ $nmap_exit -eq 0 ]; then
        # Verificar que el archivo XML se generó y tiene contenido
        if [ -f "${output_file}" ] && [ -s "${output_file}" ]; then
            log_success "Escaneo nmap completado: ${output_file}"
            # Mostrar preview rápido del XML
            local open_count=$(grep -c 'state="open"' "$output_file" 2>/dev/null || echo "0")
            log_info "Puertos abiertos detectados en XML: $open_count"
            # Devolver el path en stdout (solo esta línea)
            echo "XMLFILE:${output_file}"
        else
            log_error "El archivo XML está vacío o no se generó correctamente"
            log_error "Revisa el log: $nmap_log"
            if [ -f "$nmap_log" ]; then
                log_error "Últimas líneas del log de nmap:"
                tail -20 "$nmap_log" | while read -r log_line; do
                    log_error "  $log_line"
                done
            fi
            exit 1
        fi
    else
        log_error "Error durante el escaneo nmap (código: $nmap_exit)"
        log_error "Revisa el log: $nmap_log"
        if [ -f "$nmap_log" ]; then
            log_error "Últimas líneas del log:"
            tail -20 "$nmap_log" | while read -r log_line; do
                log_error "  $log_line"
            done
        fi
        exit 1
    fi
}

parse_nmap_results() {
    local xml_file="$1"
    
    log_info "Parseando resultados de nmap..."
    
    # Verificar que el archivo existe y no está vacío
    if [ ! -f "$xml_file" ] || [ ! -s "$xml_file" ]; then
        log_error "El archivo XML de nmap no existe o está vacío: $xml_file"
        return 1
    fi
    
    # Debug: mostrar preview del XML (solo si hay menos de 10 puertos abiertos para no saturar)
    local debug_count=$(grep -c 'state="open"' "$xml_file" 2>/dev/null || echo "0")
    if [ "$debug_count" -lt 10 ]; then
        log_info "Preview del XML (primeras 20 líneas):"
        head -20 "$xml_file" | while read -r line; do
            log_info "  $line"
        done
    else
        log_info "XML contiene $debug_count puertos abiertos (omitiendo preview)"
    fi
    
    local port_count=0
    local current_port=""
    local current_protocol="tcp"
    local current_state=""
    local current_service="unknown"
    local current_product=""
    local current_version=""
    
    # Leer el XML línea por línea y parsear de forma más robusta
    while IFS= read -r line || [ -n "$line" ]; do
        # Detectar elemento <port> con portid usando grep para extraer
        if echo "$line" | grep -q 'portid='; then
            # Extraer portid
            local extracted_port
            extracted_port=$(echo "$line" | grep -oP 'portid="\K[0-9]+' || echo "")
            
            # Si hay un portid en esta línea, es un nuevo puerto
            if [ ! -z "$extracted_port" ]; then
                # Si ya tenemos un puerto abierto guardado, almacenarlo
                if [ ! -z "$current_port" ] && [ "$current_state" = "open" ]; then
                    SERVICES["$current_port"]="$current_service"
                    VERSIONS["$current_port"]="$current_version"
                    log_success "Servicio detectado: ${current_service} en puerto ${current_port}/${current_protocol} - Versión: ${current_version:-N/A}"
                    ((port_count++))
                fi
                
                current_port="$extracted_port"
                # Intentar extraer protocolo
                current_protocol=$(echo "$line" | grep -oP 'protocol="\K[^"]+' || echo "tcp")
                current_state=""
                current_service="unknown"
                current_product=""
                current_version=""
            fi
        fi
        
        # Formato alternativo: buscar portid sin <port>
        if [[ "$line" =~ portid=\"([0-9]+)\" ]] && [ -z "$current_port" ]; then
            # Formato alternativo sin protocolo en la misma línea
            if [ ! -z "$current_port" ] && [ "$current_state" = "open" ]; then
                SERVICES["$current_port"]="$current_service"
                VERSIONS["$current_port"]="$current_version"
                log_success "Servicio detectado: ${current_service} en puerto ${current_port}/${current_protocol} - Versión: ${current_version:-N/A}"
                ((port_count++))
            fi
            
            current_port="${BASH_REMATCH[1]}"
            current_state=""
            current_service="unknown"
            current_product=""
            current_version=""
        fi
        
        # Detectar estado del puerto
        if echo "$line" | grep -q 'state="open"'; then
            current_state="open"
        fi
        
        # Solo procesar información si el puerto está abierto
        if [ "$current_state" = "open" ] && [ ! -z "$current_port" ]; then
            # Extraer nombre del servicio
            if [[ "$line" =~ name=\"([^\"]+)\" ]]; then
                current_service="${BASH_REMATCH[1]}"
            fi
            
            # Extraer product
            if [[ "$line" =~ product=\"([^\"]+)\" ]]; then
                current_product="${BASH_REMATCH[1]}"
            fi
            
            # Extraer version
            if [[ "$line" =~ version=\"([^\"]+)\" ]]; then
                current_version="${BASH_REMATCH[1]}"
            fi
        fi
        
        # Si encontramos el cierre del elemento port, procesar si estaba abierto
        if echo "$line" | grep -q '</port>' && [ ! -z "$current_port" ] && [ "$current_state" = "open" ]; then
            # Construir version_info
            local version_info=""
            if [ ! -z "$current_product" ] && [ ! -z "$current_version" ]; then
                version_info="${current_product} ${current_version}"
            elif [ ! -z "$current_product" ]; then
                version_info="$current_product"
            elif [ ! -z "$current_version" ]; then
                version_info="$current_version"
            fi
            
            # Solo guardar si no lo hemos guardado ya (evitar duplicados)
            if [ -z "${SERVICES[$current_port]:-}" ]; then
                SERVICES["$current_port"]="$current_service"
                VERSIONS["$current_port"]="$version_info"
                log_success "Servicio detectado: ${current_service} en puerto ${current_port}/${current_protocol} - Versión: ${version_info:-N/A}"
                ((port_count++))
            fi
        fi
    done < "$xml_file"
    
    # Guardar el último puerto si estaba abierto
    if [ ! -z "$current_port" ] && [ "$current_state" = "open" ]; then
        local version_info=""
        if [ ! -z "$current_product" ] && [ ! -z "$current_version" ]; then
            version_info="${current_product} ${current_version}"
        elif [ ! -z "$current_product" ]; then
            version_info="$current_product"
        elif [ ! -z "$current_version" ]; then
            version_info="$current_version"
        fi
        
        if [ -z "${SERVICES[$current_port]:-}" ]; then
            SERVICES["$current_port"]="$current_service"
            VERSIONS["$current_port"]="$version_info"
            log_success "Servicio detectado: ${current_service} en puerto ${current_port}/${current_protocol} - Versión: ${version_info:-N/A}"
            ((port_count++))
        fi
    fi
    
    if [ $port_count -eq 0 ]; then
        log_warning "No se encontraron puertos abiertos en el XML"
        log_info "Intentando método alternativo simple..."
        
        # Método alternativo ultra simple: buscar puertos abiertos con grep
        local simple_ports
        simple_ports=$(grep -B5 'state="open"' "$xml_file" | grep -oP 'portid="\K[0-9]+' | sort -u || echo "")
        
        if [ ! -z "$simple_ports" ]; then
            local simple_count=$(echo "$simple_ports" | wc -l)
            log_info "Encontrados $simple_count puertos con método simple"
            while IFS= read -r port; do
                [ -z "$port" ] && continue
                if [ -z "${SERVICES[$port]:-}" ]; then
                    SERVICES["$port"]="unknown"
                    VERSIONS["$port"]=""
                    log_success "Puerto abierto detectado: ${port} (servicio desconocido)"
                    ((port_count++))
                fi
            done <<< "$simple_ports"
        fi
    fi
    
    log_success "Total de servicios detectados: $port_count"
}

display_discovered_services() {
    log_info "═══════════════════════════════════════════════════════"
    log_info "SERVICIOS DESCUBIERTOS:"
    log_info "═══════════════════════════════════════════════════════"
    
    for port in "${!SERVICES[@]}"; do
        local service="${SERVICES[$port]}"
        local version="${VERSIONS[$port]:-Desconocida}"
        echo -e "${CYAN}Puerto ${port}:${NC} ${service} - Versión: ${version}"
    done
    
    log_info "═══════════════════════════════════════════════════════"
}

export_open_ports() {
    log_info "Exportando puertos abiertos a archivos..."
    
    # Verificar que hay puertos para exportar
    if [ ${#SERVICES[@]} -eq 0 ]; then
        log_warning "No hay puertos para exportar"
        echo "nmap -p <target>" > "$PORTS_LIST_FILE"
        echo "port,service,version" > "$PORTS_CSV_FILE"
        return
    fi
    
    # Construir lista ordenada de puertos
    local ports_sorted
    ports_sorted=$(printf "%s\n" "${!SERVICES[@]}" | sort -n)
    
    if [ -z "$ports_sorted" ]; then
        log_warning "Lista de puertos vacía"
        echo "nmap -p <target>" > "$PORTS_LIST_FILE"
        echo "port,service,version" > "$PORTS_CSV_FILE"
        return
    fi
    
    # open_ports_*.txt -> lista simple (uno por línea) y una línea con formato nmap -p
    {
        printf "%s\n" "$ports_sorted"
        echo ""
        # Línea útil para nmap:  -p 22,80,443
        local ports_csv_line
        ports_csv_line=$(echo "$ports_sorted" | tr '\n' ',' | sed 's/,$//')
        if [ ! -z "$ports_csv_line" ]; then
            echo "nmap -p $ports_csv_line <target>"
        else
            echo "nmap -p <target>"
        fi
    } > "$PORTS_LIST_FILE"
    
    # open_ports_*.csv -> CSV con encabezado: port,service,version
    {
        echo "port,service,version"
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            local svc version
            svc="${SERVICES[$p]:-unknown}"
            version="${VERSIONS[$p]:-Desconocida}"
            # Escapar comas en versión
            version=$(echo "$version" | sed 's/,/;/g')
            echo "$p,$svc,$version"
        done <<< "$ports_sorted"
    } > "$PORTS_CSV_FILE"
    
    log_success "Puertos exportados: $PORTS_LIST_FILE"
    log_success "Detalle CSV: $PORTS_CSV_FILE"
    log_info "Total de puertos exportados: $(echo "$ports_sorted" | wc -l)"
}

###############################################################################
# Funciones de búsqueda de vulnerabilidades
###############################################################################

search_exploits() {
    local service="$1"
    local version="${2:-}"
    
    log_info "Buscando exploits para: ${service} ${version}"
    
    # Primero intentar búsqueda con versión específica si está disponible
    local search_term="${service}"
    local exploit_output=""
    
    if [ ! -z "$version" ] && [ "$version" != "unknown" ]; then
        # Buscar con versión específica
        exploit_output=$(searchsploit -s "$version" 2>/dev/null | head -50)
        
        if [ -z "$exploit_output" ]; then
            # Si no encuentra con versión, buscar solo por servicio
            exploit_output=$(searchsploit "$service" 2>/dev/null | head -50)
        fi
    else
        # Búsqueda genérica
        exploit_output=$(searchsploit "$service" 2>/dev/null | head -50)
    fi
    
    # También buscar con formato web (-w para URLs)
    local web_output=$(searchsploit -w "$search_term" 2>/dev/null | grep -E "https?://" | head -20)
    
    if [ ! -z "$exploit_output" ] || [ ! -z "$web_output" ]; then
        local combined_output=""
        [ ! -z "$exploit_output" ] && combined_output="$combined_output$exploit_output"
        [ ! -z "$web_output" ] && combined_output="$combined_output\n--- Web Exploits ---\n$web_output"
        
        log_exploit "Exploits encontrados para ${search_term}:"
        echo -e "$combined_output"
        
        # Almacenar solo los primeros líneas para el reporte
        EXPLOITS["${service}"]="$(echo -e "$combined_output" | head -50)"
    else
        log_warning "No se encontraron exploits para ${search_term}"
    fi
}

search_cves_local() {
    local service="$1"
    local version="${2:-}"
    
    log_info "Buscando CVEs para: ${service} ${version}"
    
    local cves=""
    
    # Intentar con formato JSON si jq está disponible
    if command -v jq &> /dev/null; then
        local json_result=$(searchsploit -j "$service" 2>/dev/null)
        if [ ! -z "$json_result" ]; then
            cves=$(echo "$json_result" | jq -r '.RESULTS_EXPLOIT[] | "\(.Title) - \(.Type) - \(.ID)"' 2>/dev/null | head -10)
        fi
    fi
    
    # Si no tenemos resultados con JSON, usar búsqueda estándar
    if [ -z "$cves" ]; then
        local exploit_list=$(searchsploit "$service" 2>/dev/null | grep -E "^\d+.*" | head -10)
        
        if [ ! -z "$exploit_list" ]; then
            cves="$exploit_list"
        fi
    fi
    
    if [ ! -z "$cves" ]; then
        CVES["${service}"]="$cves"
        log_success "Vulnerabilidades encontradas para ${service}"
        echo -e "${CYAN}CVEs/Exploits:${NC}"
        echo "$cves" | head -5
    else
        log_warning "No se encontraron CVEs explícitos para ${service}"
    fi
}

query_shodan_api() {
    local service="$1"
    local version="${2:-}"
    
    if [ -z "$SHODAN_API_KEY" ]; then
        return
    fi
    
    log_info "Consultando API de Shodan para: ${service} ${version}"
    
    # Construir query optimizada para Shodan
    local query="product:${service}"
    if [ ! -z "$version" ] && [ "$version" != "unknown" ]; then
        # Intentar extraer solo la parte relevante de la versión
        local version_clean=$(echo "$version" | awk '{print $1}')
        query="${query} version:${version_clean}"
    fi
    
    # Consultar API de Shodan con timeout
    local result=$(curl -s --max-time 10 \
        "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${query}" \
        2>/dev/null)
    
    if [ $? -eq 0 ] && [ ! -z "$result" ] && [ "$result" != "null" ]; then
        if command -v jq &> /dev/null; then
            local count=$(echo "$result" | jq -r '.total' 2>/dev/null)
            
            if [ "$count" != "0" ] && [ "$count" != "null" ] && [ ! -z "$count" ]; then
                # Guardar información más detallada
                local info_str="${count} hosts encontrados"
                
                # Intentar extraer datos adicionales
                local cvss=$(echo "$result" | jq -r '.matches[0].info' 2>/dev/null)
                if [ ! -z "$cvss" ] && [ "$cvss" != "null" ]; then
                    info_str="${info_str} - Info adicional disponible"
                fi
                
                SHODAN_INFO["${service}"]="$info_str"
                log_success "Shodan: ${info_str}"
            else
                log_warning "Shodan no encontró resultados para ${service}"
            fi
        else
            # Sin jq, hacer parsing básico
            if echo "$result" | grep -q '"total"'; then
                local count=$(echo "$result" | grep -oP '"total":\s*\K[0-9]+' || echo "0")
                if [ "$count" != "0" ]; then
                    SHODAN_INFO["${service}"]="${count} hosts encontrados"
                    log_success "Shodan reporta ${count} hosts con ${service}"
                fi
            fi
        fi
    else
        log_warning "No se pudo obtener información de Shodan para ${service}"
    fi
}

###############################################################################
# Funciones de análisis y recomendaciones
###############################################################################

analyze_vulnerabilities() {
    log_info "Analizando vulnerabilidades descubiertas..."
    
    for port in "${!SERVICES[@]}"; do
        local service="${SERVICES[$port]}"
        local version="${VERSIONS[$port]:-}"
        
        # Buscar exploits y CVEs
        search_exploits "$service" "$version"
        search_cves_local "$service" "$version"
        query_shodan_api "$service" "$version"
    done
}

prioritize_exploits() {
    log_info "Priorizando exploits basado en criticidad..."
    
    local critical_services=("ssh" "http" "https" "ftp" "smb" "telnet" "mysql" "postgres" "redis" "mongo" "rdp" "vnc")
    local high_risk_services=("webmin" "jenkins" "apache" "nginx" "tomcat" "wordpress")
    
    log_info "═══════════════════════════════════════════════════════"
    log_info "ANÁLISIS DE CRITICIDAD:"
    log_info "═══════════════════════════════════════════════════════"
    
    for port in "${!SERVICES[@]}"; do
        local service="${SERVICES[$port]}"
        local version="${VERSIONS[$port]:-}"
        local exploit_count=0
        
        if [ ! -z "${EXPLOITS[$service]:-}" ]; then
            # Contar entradas de searchsploit: líneas con ID o rutas/URLs
            exploit_count=$(echo "${EXPLOITS[$service]}" | grep -E -c "(^\s*[0-9]{3,}|https?://|/exploits?/|/shellcodes?/)" || echo "0")
        fi
        
        if [[ " ${critical_services[*]} " =~ " ${service} " ]]; then
            if [ "$exploit_count" -gt 0 ]; then
                log_exploit "${RED}[CRÍTICO - ALTA PRIORIDAD]${NC} Servicio ${service} en puerto ${port}"
                log_exploit "Versión: ${version} | Exploits encontrados: ${exploit_count}"
            else
                log_warning "${YELLOW}[CRÍTICO]${NC} Servicio ${service} en puerto ${port} - Revisar configuración"
            fi
        elif [[ " ${high_risk_services[*]} " =~ " ${service} " ]]; then
            if [ "$exploit_count" -gt 0 ]; then
                log_warning "${YELLOW}[RIESGO ALTO]${NC} Servicio ${service} en puerto ${port}"
                log_warning "Versión: ${version} | Exploits encontrados: ${exploit_count}"
            fi
        fi
    done
    
    log_info "═══════════════════════════════════════════════════════"
}

generate_recommendations() {
    log_info "Generando recomendaciones de explotación..."
    
    local recommendations=()
    local high_priority=()
    local medium_priority=()
    local low_priority=()
    
    for port in "${!SERVICES[@]}"; do
        local service="${SERVICES[$port]}"
        local version="${VERSIONS[$port]:-}"
        local exploits="${EXPLOITS[$service]:-}"
        local cves="${CVES[$service]:-}"
        local shodan_info="${SHODAN_INFO[$service]:-}"
        
        if [ ! -z "$exploits" ] || [ ! -z "$cves" ]; then
            local priority="medium"
            local description="Puerto ${port} - ${service}\n"
            description+="  Versión: ${version}\n"
            
            if [ ! -z "$cves" ]; then
                description+="   CVEs conocidos encontrados\n"
                priority="high"
            fi
            
            if [ ! -z "$exploits" ]; then
                description+="   Exploits disponibles\n"
                priority="high"
            fi
            
            if [ ! -z "$shodan_info" ]; then
                description+="   Shodan: ${shodan_info}\n"
            fi
            
            # Obtener primer exploit como recomendación
            if [ ! -z "$exploits" ]; then
                local first_exploit=$(echo "$exploits" | grep -m1 "Exploit Title" || echo "")
                if [ ! -z "$first_exploit" ]; then
                    description+="   Primer exploit: $(echo "$first_exploit" | sed 's/Exploit Title: //')\n"
                fi
            fi
            
            description+=""
            
            case $priority in
                high)
                    high_priority+=("$description")
                    ;;
                medium)
                    medium_priority+=("$description")
                    ;;
                low)
                    low_priority+=("$description")
                    ;;
            esac
        fi
    done
    
    if [ ${#high_priority[@]} -gt 0 ] || [ ${#medium_priority[@]} -gt 0 ] || [ ${#low_priority[@]} -gt 0 ]; then
        log_info "═══════════════════════════════════════════════════════"
        log_info "RECOMENDACIONES DE EXPLOTACIÓN:"
        log_info "═══════════════════════════════════════════════════════"
        
        if [ ${#high_priority[@]} -gt 0 ]; then
            log_warning "${RED}ALTA PRIORIDAD:${NC}"
            for rec in "${high_priority[@]}"; do
                echo -e -n "$rec"
            done
        fi
        
        if [ ${#medium_priority[@]} -gt 0 ]; then
            log_warning "${YELLOW}MEDIA PRIORIDAD:${NC}"
            for rec in "${medium_priority[@]}"; do
                echo -e -n "$rec"
            done
        fi
        
        if [ ${#low_priority[@]} -gt 0 ]; then
            log_info "${GREEN}BAJA PRIORIDAD:${NC}"
            for rec in "${low_priority[@]}"; do
                echo -e -n "$rec"
            done
        fi
        
        log_info "═══════════════════════════════════════════════════════"
    else
        log_success "No se encontraron vulnerabilidades con exploits conocidos"
    fi
}

###############################################################################
# Generación de reporte
###############################################################################

generate_report() {
    log_info "Generando reporte completo..."
    
    {
        cat << EOF
╔═══════════════════════════════════════════════════════════════╗
║                    REPORTE DE VULNERABILIDADES                ║
║                    Fecha: $(date)                            ║
╚═══════════════════════════════════════════════════════════════╝

OBJETIVO: ${TARGET}
TIMESTAMP: ${TIMESTAMP}

═══════════════════════════════════════════════════════════════
SERVICIOS DESCUBIERTOS
═══════════════════════════════════════════════════════════════
EOF
        
        for port in "${!SERVICES[@]}"; do
            echo "Puerto: ${port}"
            echo "  Servicio: ${SERVICES[$port]}"
            echo "  Versión: ${VERSIONS[$port]:-Desconocida}"
            echo ""
        done
        
        cat << EOF
═══════════════════════════════════════════════════════════════
EXPLOITS Y CVEs ENCONTRADOS
═══════════════════════════════════════════════════════════════
EOF
        
        for service in "${!EXPLOITS[@]}"; do
            echo "Servicio: ${service}"
            echo "${EXPLOITS[$service]}"
            echo ""
        done
        
        for service in "${!CVES[@]}"; do
            echo "CVEs para ${service}:"
            echo "${CVES[$service]}"
            echo ""
        done
        
        cat << EOF
═══════════════════════════════════════════════════════════════
INFORMACIÓN ADICIONAL DE SHODAN
═══════════════════════════════════════════════════════════════
EOF
        
        for service in "${!SHODAN_INFO[@]}"; do
            echo "${service}: ${SHODAN_INFO[$service]} hosts encontrados"
        done
        
        cat << EOF

═══════════════════════════════════════════════════════════════
NOTAS IMPORTANTES
═══════════════════════════════════════════════════════════════
- Este reporte fue generado en un entorno controlado local
- Todos los exploits listados deben ser probados con precaución
- Se recomienda validar las vulnerabilidades antes de explotar
- Mantener registros apropiados de todas las actividades

EOF
    } > "${REPORT_FILE}"
    
    log_success "Reporte generado: ${REPORT_FILE}"
}

###############################################################################
# Función principal
###############################################################################

main() {
    print_banner
    
    if [ -z "$TARGET" ]; then
        log_error "No se proporcionó un objetivo"
        usage
    fi
    
    log_info "Iniciando análisis del objetivo: ${TARGET}"
    log_warning "Recordatorio: Este script está diseñado únicamente para entornos controlados locales"
    
    check_dependencies
    init_directories
    
    # Ejecutar escaneo nmap
    # La función nmap_scan imprime logs pero devuelve XMLFILE:path al final
    local nmap_output
    nmap_output=$(nmap_scan "$TARGET" 2>&1 | grep "^XMLFILE:" | cut -d: -f2-)
    
    # Si no lo encontramos así, intentar obtenerlo del timestamp
    if [ -z "$nmap_output" ] || [ ! -f "$nmap_output" ]; then
        nmap_output="${OUTPUT_DIR}/nmap_scan_${TIMESTAMP}.xml"
        log_info "Intentando usar archivo por timestamp: $nmap_output"
        if [ ! -f "$nmap_output" ]; then
            log_error "No se pudo encontrar el archivo XML de nmap"
            log_error "Buscando en: $OUTPUT_DIR"
            if [ -d "$OUTPUT_DIR" ]; then
                ls -la "$OUTPUT_DIR" | tail -10
            else
                log_error "El directorio $OUTPUT_DIR no existe"
            fi
            exit 1
        fi
    fi
    
    log_info "Archivo XML a parsear: $nmap_output"
    
    # Parsear resultados
    parse_nmap_results "$nmap_output"
    
    # Mostrar servicios descubiertos
    display_discovered_services
    
    # Exportar puertos abiertos a archivos
    export_open_ports
    
    # Analizar vulnerabilidades
    analyze_vulnerabilities
    
    # Priorizar y recomendar
    prioritize_exploits
    generate_recommendations
    
    # Generar reporte
    generate_report
    
    log_success "═══════════════════════════════════════════════════════"
    log_success "Análisis completado exitosamente"
    log_success "Reporte guardado en: ${REPORT_FILE}"
    log_success "═══════════════════════════════════════════════════════"
}

# Ejecutar script principal
main "$@"

