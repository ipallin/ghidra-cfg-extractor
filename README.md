# ghidra-cfg-extractor

Herramientas para extraer grafos de flujo de control (CFG) de binarios compilados
utilizando Ghidra en modo *headless*.

## Requisitos

- [Ghidra](https://ghidra-sre.org/) instalado localmente. Puedes indicar la
  ubicación mediante la variable de entorno `GHIDRA_INSTALL_DIR` o con el
  argumento `--ghidra-install` del script.
- Python 3.10 o superior para ejecutar el script `extract_cfg.py`.

## Uso

```bash
python extract_cfg.py --ghidra-install /ruta/a/ghidra \
  --output-dir cfgs \
  /ruta/al/binario1 /ruta/al/binario2
```

Para cada binario analizado se generará un archivo `*.cfg.<formato>` en el
directorio indicado con `--output-dir`. El contenido incluye la información
básica del programa junto con la lista de bloques, las aristas del CFG y la
secuencia de instrucciones de cada bloque para la función de entrada
seleccionada. El formato por defecto es GraphML, pero también se puede
exportar a JSON.

### Opciones destacadas

- `--keep-project`: conserva el proyecto temporal de Ghidra creado durante el
  análisis.
- `--overwrite`: permite sobreescribir archivos de salida existentes.
- `--script`: ruta personalizada a un *post-script* de Ghidra. Por defecto se
  utiliza `ghidra_scripts/export_cfg.py` incluido en este repositorio.
- `--language-id`: fuerza el *language*/*processor* de Ghidra (por ejemplo,
  `x86:LE:32:default`) cuando la detección automática no funciona.
- `--format`: elige el formato de salida (`json` o `graphml`). Por defecto se
  exporta en GraphML.
- `--entry-address`: indica manualmente la dirección de la función de entrada
  cuando no exista una función llamada `main` que pueda detectarse
  automáticamente.
- `--workers`: número de análisis concurrentes a ejecutar. Por defecto el
  script utiliza tantos *workers* como núcleos de CPU detectados en la
  máquina (valor devuelto por `os.cpu_count()`). Establece `--workers 1` para
  comportamiento secuencial. Ten en cuenta que cada *worker* lanza su propia
  instancia de `analyzeHeadless` y puede consumir memoria y CPU significativamente.
  
- `--zip-password`: contraseña(s) a probar al extraer archivos ZIP cifrados.
  Puede pasarse varias veces para intentar múltiples contraseñas en orden. Si
  no se encuentra una contraseña, el script intentará la contraseña por
  defecto `infected` y, si está disponible, usará herramientas del sistema
  como `7z` o `unzip` para soportar distintos esquemas de cifrado.

## Concurrencia y recursos

El script ahora puede ejecutar múltiples análisis de Ghidra en paralelo. Cada
análisis crea su propio directorio de proyecto temporal y ejecuta
`analyzeHeadless` sobre un binario. Ejecutar muchos *workers* simultáneos puede
consumir mucha memoria y CPU; ajusta `--workers` según la capacidad de tu
máquina. Un buen punto de partida es usar el número de núcleos físicos o
reducir el valor si observas alta contención.

## Ejemplos de uso

Analizar todos los archivos en un directorio con tantos workers como CPUs:

```bash
python extract_cfg.py --input-dir /ruta/a/inputs --output-dir cfgs
```

Forzar 4 análisis concurrentes y conservar los proyectos temporales para
diagnóstico:

```bash
python extract_cfg.py --input-dir /ruta/a/inputs --output-dir cfgs --workers 4 --keep-project
```

Analizar un archivo ZIP cifrado probando varias contraseñas y exportando en
formato JSON:

```bash
python extract_cfg.py --input-dir /ruta/a/inputs --output-dir cfgs --zip-password secret1 --zip-password secret2 --format json
```

Analizar todas las funciones en cada binario (no sólo `main`):

```bash
python extract_cfg.py --input-dir /ruta/a/inputs --output-dir cfgs --all-functions
```

Ejecutar secuencialmente (útil para depuración o entornos con pocos recursos):

```bash
python extract_cfg.py --input-dir /ruta/a/inputs --output-dir cfgs --workers 1
```

## Script de Ghidra

El archivo `ghidra_scripts/export_cfg.py` es un script de Ghidra (Jython) que se
encarga de localizar la función `main` (o la dirección indicada con
`--entry-address`), recorrer sus bloques y generar el grafo de flujo de control
incluyendo las instrucciones de cada bloque. Actualmente admite los formatos
JSON y GraphML y se ejecuta automáticamente mediante la opción `-postScript` del
comando `analyzeHeadless` de Ghidra.
