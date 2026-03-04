## Formas de uso:

### Recomendable: Descargar repositorio completo con wget https://github.com/danuch8/Practicas-MHE-Tajamar/new/main/linpeas_parser en la máquina a testear.

## Linux - linpeas_parser.sh

- **Con parámetro `-l`**:  
  Ejecuta primero el `linpeas.sh`, vuelca su output en un archivo `outputLP.txt`, y acto seguido el parseador lee el `outputLP.txt` y opera a partir de él.  
  Uso en un solo comando:

  ```bash
  bash linpeas_parser.sh -l
  ```

- **Sin parámetro**:  
  Ejecuta el `linpeas_parser.sh` operando a partir de un `outputLP.txt` en el que hayas volcado previamente tú el output de un `linpeas.sh`.  
  Útil si ya has ejecutado tú linpeas aparte o quieres usar un linpeas diferente, como el FAT, el Small o uno custom.  
  Uso muy simple:

  ```bash
  bash linpeas_parser.sh
  ```

## Windows - winpeas_parser.ps1

1. **Generar el output de winPEAS (recomendado)**:

   Desde `cmd` en la máquina Windows objetivo:

   ```cmd
   cmd /c "winPEAS.bat > outputWP.txt"
   ```

   - Deja que winPEAS termine.
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

     entonces puedes ejecutar:

     ```powershell
     powershell -ExecutionPolicy Bypass -File .\winpeas_parser.ps1 -InputFile .\mi_output_winpeas.txt
     ```

   - **`-RunWinPEAS`** (opcional):  
     Intenta ejecutar automáticamente `.\winPEAS.bat` y guardar su salida en el fichero indicado por `-InputFile` (por defecto `outputWP.txt`):

     ```powershell
     powershell -ExecutionPolicy Bypass -File .\winpeas_parser.ps1 -RunWinPEAS
     ```

     Ten en cuenta que `winPEAS.bat` hace un `PAUSE` al final, por lo que tendrás que pulsar una tecla en la consola para que termine y el parser continúe.
