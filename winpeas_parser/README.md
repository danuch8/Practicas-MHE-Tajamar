## Windows - winpeas_parser.ps1

1. **Generar el output de winPEAS (recomendado)**:

   Desde `cmd` en la máquina Windows objetivo:

   ```cmd
   cmd /c "winPEAS.bat > outputWP.txt"
   ```

   - Dejar que winPEAS termine.
   - El output se guardará en `outputWP.txt` en el directorio actual.

2. **Ejecutar el parser en PowerShell**:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\winpeas_parser.ps1
   ```

   - Por defecto, leerá `outputWP.txt`.
   - Generará un resumen en un fichero `winpeas_summary_YYYYMMDD_HHMMSS.txt`.

3. **Parámetros útiles de `winpeas_parser.ps1`**:

   - **`-InputFile <ruta>`**:  
     Si guardas el output de `winPEAS.bat` con otro nombre, por ejemplo:

     ```cmd
     cmd /c "winPEAS.bat > mi_output_winpeas.txt"
     ```

     entonces podrás ejecutar:

     ```powershell
     powershell -ExecutionPolicy Bypass -File .\winpeas_parser.ps1 -InputFile .\mi_output_winpeas.txt
     ```

   - **`-RunWinPEAS`** (opcional):  
     Intenta ejecutar automáticamente `.\winPEAS.bat` y guardar su salida en el fichero indicado por `-InputFile` (por defecto `outputWP.txt`):

     ```powershell
     powershell -ExecutionPolicy Bypass -File .\winpeas_parser.ps1 -RunWinPEAS
     ```

     Se debe tener en cuenta que `winPEAS.bat` hace un `PAUSE` al final, por lo que hay que pulsar una tecla en la consola para que termine y el parser continúe (por ejemplo pulsar ENTER o Ñ de España)
