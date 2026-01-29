## Formas de uso:

### Recomendable: Descargar repositorio completo con wget https://github.com/danuch8/Practicas-MHE-Tajamar/new/main/linpeas_parser en la máquina a testear.

## -Con parámetro -l: Ejecuta primero el linpeas.sh, vuelca su output en un archivo outputLP.txt, y acto seguido el parseador lee el outputLP.txt y opera a partir de él. Todo en un mismo comando: "bash linpeas_parser.sh -l"

## -Sin parámetro: Ejecuta el linpeas_parser.sh operando a partir de un outputLP.txt qen el que hayas volcado previamente tú el output de un linpeas.sh. Útil si ya has ejecutado tú linpeas aparte o quieres usar un linpeas diferente, como el FAT, el Small o uno custom. Uso muy simple: "bash linpeas_server.sh"
